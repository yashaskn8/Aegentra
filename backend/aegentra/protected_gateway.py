"""Fail-closed protected-origin admission for one enrolled static resource.

All bytes are buffered and verified BEFORE any success response. Fresh signed
heads are fetched twice and the independent security veto is fetched LAST.
No stale cache, fallback origin, redirects, alternate encoding, 304, range or
mutable object selection. Actual production ingress must prevent bypass.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import re
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

import rfc8785
from pydantic import ValidationError

from aegentra.content_manifest import ManifestError, strict_json
from aegentra.fixed_delivery import FixedStaticProfile, UnsupportedDelivery
from aegentra.gateway_signatures import (
    AdmissionDenied, HeadSnapshot, SignedHead, SignedVeto,
    verify_head, verify_veto,
)
from aegentra.witness_crypto import WitnessBody, WitnessArchiveRef
from aegentra.witness_archive import MAX_WITNESS

MAX_PROTECTED_BYTES = 1024 * 1024
MAX_DECISION_SECONDS = 2.0
_DISALLOWED_REQUEST_HEADERS = frozenset({
    "range", "if-match", "if-none-match", "if-modified-since",
    "if-unmodified-since", "if-range",
})
@dataclass(frozen=True)
class EnrolledResource:
    org_id: UUID
    target_id: UUID
    incarnation: UUID
    host: str
    path: str
    origin_bucket: str
    allowed_origin_prefix: str
    witness_bucket: str
    content_type: str
    fixed_profile: FixedStaticProfile


@dataclass(frozen=True)
class PreparedResponse:
    body: bytes
    headers: dict[str, str]
    revision: int
    attempt_sequence: int


def delivery_headers(resource: EnrolledResource, content: bytes) -> dict[str, str]:
    """No generic HTML or script-src 'self': only fixed generated entry + exact JS."""
    try:
        if resource.host != resource.fixed_profile.host:
            raise UnsupportedDelivery("host does not match enrolled profile")
        headers = resource.fixed_profile.headers(path=resource.path, content=content)
        if headers["content-type"] != resource.content_type:
            raise UnsupportedDelivery("resource media type differs from fixed profile")
        return headers
    except UnsupportedDelivery as exc:
        raise AdmissionDenied("unqualified original HTML or JavaScript bytes") from exc


def delivery_profile_sha256(headers: dict[str, str]) -> str:
    return hashlib.sha256(
        b"aegentra.delivery.profile.v1\x00" + rfc8785.dumps(headers)
    ).hexdigest()


def _witness_from_bytes(raw: bytes) -> tuple[WitnessBody, bytes]:
    if not 0 < len(raw) <= MAX_WITNESS:
        raise AdmissionDenied("missing or oversized immutable certificate")
    try:
        decoded = strict_json(raw, max_bytes=MAX_WITNESS)
        if (
            not isinstance(decoded, dict)
            or set(decoded) != {"body", "signature_der_hex"}
            or rfc8785.dumps(decoded) != raw
            or not isinstance(decoded["signature_der_hex"], str)
        ):
            raise AdmissionDenied("noncanonical witness certificate")
        body = WitnessBody.model_validate(decoded["body"])
        signature = bytes.fromhex(decoded["signature_der_hex"])
        return body, signature
    except (ValueError, ManifestError, ValidationError, KeyError, TypeError) as exc:
        raise AdmissionDenied("witness certificate invalid") from exc


def _verify_witness_signature(
    body: WitnessBody, signature: bytes, public_key_der: bytes
) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    if not 8 <= len(signature) <= 128:
        raise AdmissionDenied("invalid witness signature length")
    try:
        key = serialization.load_der_public_key(public_key_der)
        if (
            not isinstance(key, ec.EllipticCurvePublicKey)
            or not isinstance(key.curve, ec.SECP256R1)
        ):
            raise AdmissionDenied("witness verification key mismatch")
        from aegentra.witness_crypto import witness_message
        key.verify(signature, witness_message(body), ec.ECDSA(hashes.SHA256()))
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise AdmissionDenied("independent witness signature invalid") from exc


class ProtectedAdmission:
    def __init__(
        self,
        *,
        resource: EnrolledResource,
        head_public_der: bytes,
        veto_public_der: bytes,
        witness_public_der: bytes,
        fetch_head: Callable[[str], Awaitable[SignedHead]],
        fetch_veto: Callable[[str], Awaitable[SignedVeto]],
        fetch_witness: Callable[[WitnessArchiveRef], Awaitable[bytes]],
        fetch_origin: Callable[[str, str, str], Awaitable[bytes]],
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        max_decision_seconds: float = MAX_DECISION_SECONDS,
    ) -> None:
        if (
            max_decision_seconds <= 0
            or max_decision_seconds > MAX_DECISION_SECONDS
            or not resource.allowed_origin_prefix.startswith("published/")
            or resource.host != resource.fixed_profile.host
            or resource.path not in {
                resource.fixed_profile.entry_path, resource.fixed_profile.script_path
            }
            or resource.content_type != (
                "text/html; charset=utf-8"
                if resource.path == resource.fixed_profile.entry_path
                else "text/javascript; charset=utf-8"
            )
        ):
            raise ValueError("incomplete protected enrollment")
        self.resource = resource
        self.head_public_der = head_public_der
        self.veto_public_der = veto_public_der
        self.witness_public_der = witness_public_der
        self.fetch_head = fetch_head
        self.fetch_veto = fetch_veto
        self.fetch_witness = fetch_witness
        self.fetch_origin = fetch_origin
        self.clock = clock
        self.max_seconds = max_decision_seconds

    async def admit(
        self, *, method: str, host: str, path: str,
        request_headers: dict[str, str],
    ) -> PreparedResponse:
        """No network response bytes leave this method, including on failure."""
        if (
            method != "GET" or host != self.resource.host or path != self.resource.path
            or any(name.lower() in _DISALLOWED_REQUEST_HEADERS for name in request_headers)
        ):
            raise AdmissionDenied("request is outside the exact enrolled delivery profile")
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.max_seconds

        async def bounded(operation: Awaitable):
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise AdmissionDenied("protected admission time budget exhausted")
            try:
                return await asyncio.wait_for(operation, timeout=remaining)
            except (asyncio.TimeoutError, OSError, ConnectionError) as exc:
                raise AdmissionDenied("required independent service unavailable") from exc

        first_nonce = secrets.token_urlsafe(32)
        first = await bounded(self.fetch_head(first_nonce))
        head = verify_head(
            first, pinned_key_der=self.head_public_der,
            nonce=first_nonce, org_id=self.resource.org_id,
            target_id=self.resource.target_id, incarnation=self.resource.incarnation,
            host=host, path=path, now=self.clock(),
        )
        prefix = (
            f"certificates/v1/{self.resource.org_id.hex}/"
            f"{self.resource.incarnation.hex}/{self.resource.target_id.hex}/"
        )
        if (
            head.fixed_bundle_sha256 != self.resource.fixed_profile.manifest_sha256()
            or head.witness_bucket != self.resource.witness_bucket
            or head.witness_key != prefix + f"{head.attempt_sequence:020d}"
            or head.origin_bucket != self.resource.origin_bucket
            or not head.origin_key.startswith(self.resource.allowed_origin_prefix)
            or ".." in head.origin_key.split("/")
            or head.origin_key.endswith("/")
        ):
            raise AdmissionDenied("resource points outside pinned immutable storage")

        ref = WitnessArchiveRef(
            bucket=head.witness_bucket, key=head.witness_key,
            version_id=head.witness_version_id,
            object_sha256=head.witness_sha256,
        )
        witness_raw = await bounded(self.fetch_witness(ref))
        if (
            not isinstance(witness_raw, bytes)
            or not hmac.compare_digest(
                hashlib.sha256(witness_raw).hexdigest(), head.witness_sha256
            )
        ):
            raise AdmissionDenied("witness bytes differ from exact object reference")
        certificate, signature = _witness_from_bytes(witness_raw)
        _verify_witness_signature(
            certificate, signature, self.witness_public_der
        )
        if (
            certificate.org_id != head.org_id
            or certificate.target_id != head.target_id
            or certificate.incarnation != head.incarnation
            or certificate.attempt_sequence != head.attempt_sequence
            or certificate.prior_published_revision != head.published_revision - 1
            or certificate.content_sha256 != head.content_sha256
            or certificate.delivery_profile_sha256 != head.delivery_profile_sha256
            or certificate.fixed_bundle_sha256 != head.fixed_bundle_sha256
        ):
            raise AdmissionDenied("witness not bound to published head")

        original = await bounded(self.fetch_origin(
            head.origin_bucket, head.origin_key, head.origin_version_id
        ))
        if (
            not isinstance(original, bytes)
            or not 0 < len(original) <= MAX_PROTECTED_BYTES
            or not hmac.compare_digest(
                hashlib.sha256(original).hexdigest(), head.content_sha256
            )
        ):
            raise AdmissionDenied("origin representation differs from signed digest")
        headers = delivery_headers(self.resource, original)
        if not hmac.compare_digest(
            delivery_profile_sha256(headers), head.delivery_profile_sha256
        ):
            raise AdmissionDenied("delivery headers differ from signed profile")

        # Recheck the PRIMARY head after prebuffering; old head cannot silently
        # survive a publish, HOLD transition or STOP that races an S3 read.
        nonce_two = secrets.token_urlsafe(32)
        final_head = verify_head(
            await bounded(self.fetch_head(nonce_two)),
            pinned_key_der=self.head_public_der,
            nonce=nonce_two, org_id=self.resource.org_id,
            target_id=self.resource.target_id, incarnation=self.resource.incarnation,
            host=host, path=path, now=self.clock(),
        )
        if final_head != head.model_copy(update={
            "request_nonce": nonce_two,
            "issued_at": final_head.issued_at,
            "expires_at": final_head.expires_at,
        }):
            raise AdmissionDenied("published head changed during admission")

        # The independent veto and current root must be fetched LAST.
        veto_nonce = secrets.token_urlsafe(32)
        verify_veto(
            await bounded(self.fetch_veto(veto_nonce)),
            pinned_key_der=self.veto_public_der,
            nonce=veto_nonce, org_id=self.resource.org_id,
            incarnation=self.resource.incarnation, now=self.clock(),
            minimum_root_generation=certificate.security_root_generation,
        )
        if loop.time() >= deadline:
            raise AdmissionDenied("protected admission deadline elapsed")
        return PreparedResponse(
            body=original, headers=headers,
            revision=head.published_revision,
            attempt_sequence=head.attempt_sequence,
        )
