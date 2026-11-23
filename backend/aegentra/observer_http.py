"""Independent native HTTPS readback of the exact enrolled static resource.

Readback measures client-facing representation bytes; it does not execute,
import or evaluate JavaScript. A verified signed head is required before
sampling. An outage raises ReadbackUnavailable rather than forging a result.
"""
from __future__ import annotations

import asyncio
import hashlib
import math
import secrets
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from uuid import UUID, uuid4

import httpx
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from aegentra.fixed_delivery import FixedStaticProfile
from aegentra.gateway_signatures import (
    SignedHead, verify_head,
)
from aegentra.observation_crypto import (
    ObservationBody, SignedObservation, observation_message,
)

MAX_READBACK = 1024 * 1024
_MEASURED_HEADERS = (
    "cache-control", "content-type", "content-length",
    "content-security-policy", "x-content-type-options",
    "cross-origin-resource-policy",
)


class ReadbackUnavailable(ValueError):
    pass


def observed_profile_sha256(headers: httpx.Headers) -> str:
    """Hash the received header values, not the desired config values."""
    actual: dict[str, str] = {}
    for name in _MEASURED_HEADERS:
        values = headers.get_list(name)
        # Missing or duplicated protected headers are measured as a
        # deterministic mismatch, never replaced with expected values.
        actual[name] = (
            values[0] if len(values) == 1
            else "__missing_or_duplicated_protected_header__"
        )
    return hashlib.sha256(
        b"aegentra.delivery.profile.v1\x00" + rfc8785.dumps(actual)
    ).hexdigest()


class KmsObserverSigner:
    def __init__(self, *, kms, key_id: str, public_der: bytes):
        if not key_id:
            raise ValueError("independent observer KMS key ID is required")
        self.kms = kms
        self.key_id = key_id
        self.public_der = public_der

    def sign(self, body: ObservationBody) -> SignedObservation:
        message = observation_message(body)
        if len(message) > 4096:
            raise ReadbackUnavailable("observation exceeds KMS RAW signing bound")
        response = self.kms.sign(
            KeyId=self.key_id,
            Message=message,
            MessageType="RAW",
            SigningAlgorithm="ECDSA_SHA_256",
        )
        signature = response.get("Signature")
        if not isinstance(signature, bytes):
            raise ReadbackUnavailable("observer KMS signature missing")
        try:
            public = serialization.load_der_public_key(self.public_der)
            if (
                not isinstance(public, ec.EllipticCurvePublicKey)
                or not isinstance(public.curve, ec.SECP256R1)
            ):
                raise ReadbackUnavailable("unsupported observer public key")
            public.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise ReadbackUnavailable("observer signing identity mismatch") from exc
        return SignedObservation(body, signature)


class NativeReadbackObserver:
    def __init__(
        self, *,
        org_id: UUID, target_id: UUID, incarnation: UUID,
        profile: FixedStaticProfile, path: str,
        cohort: str, observer_key_id: str,
        head_key_der: bytes,
        fetch_head: Callable[[str], Awaitable[SignedHead]],
        signer: KmsObserverSigner,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        timeout: float = 2.0,
    ):
        if (
            path not in {profile.entry_path, profile.script_path}
            or not cohort or len(cohort) > 64
            or not observer_key_id
            or type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or timeout <= 0 or timeout > 2.0
        ):
            raise ValueError("observer enrolled profile is incomplete")
        self.org_id = org_id
        self.target_id = target_id
        self.incarnation = incarnation
        self.profile = profile
        self.path = path
        self.cohort = cohort
        self.observer_key_id = observer_key_id
        self.head_key_der = head_key_der
        self.fetch_head = fetch_head
        self.signer = signer
        self.clock = clock
        self.timeout = timeout

    async def measure(self, client: httpx.AsyncClient) -> SignedObservation:
        nonce = secrets.token_urlsafe(32)
        try:
            envelope = await self.fetch_head(nonce)
            head = verify_head(
                envelope, pinned_key_der=self.head_key_der,
                nonce=nonce, org_id=self.org_id,
                target_id=self.target_id, incarnation=self.incarnation,
                host=self.profile.host, path=self.path,
                now=self.clock(),
            )
        except Exception as exc:
            raise ReadbackUnavailable("fresh signed authority head unavailable") from exc
        if head.fixed_bundle_sha256 != self.profile.manifest_sha256():
            raise ReadbackUnavailable("signed head is not the enrolled fixed bundle")

        url = f"https://{self.profile.host}{self.path}"
        try:
            # httpx timeouts bound individual network operations, not the total
            # duration of a response that slowly streams bytes forever.
            async with asyncio.timeout(self.timeout):
                async with client.stream(
                    "GET", url, headers={
                        "Accept-Encoding": "identity", "Cache-Control": "no-store",
                    }, follow_redirects=False, timeout=self.timeout,
                ) as response:
                    if response.headers.get("content-encoding", "identity") != "identity":
                        raise ReadbackUnavailable("encoded representation cannot be measured")
                    observed_status = response.status_code
                    profile_hash = observed_profile_sha256(response.headers)
                    content = bytearray()
                    complete = True
                    async for chunk in response.aiter_raw():
                        if len(content) + len(chunk) > MAX_READBACK:
                            complete = False
                            break
                        content.extend(chunk)
        except (httpx.HTTPError, OSError, TimeoutError) as exc:
            raise ReadbackUnavailable("client-facing response could not be sampled") from exc
        observed = hashlib.sha256(content).hexdigest()
        measured_at = self.clock()
        if measured_at.tzinfo is None:
            raise ReadbackUnavailable("trusted observer clock unavailable")
        body = ObservationBody(
            kind="aegentra.observer.readback.v1",
            audience="aegentra-release-observer",
            observation_id=uuid4(), incarnation=self.incarnation,
            org_id=self.org_id, target_id=self.target_id,
            host=self.profile.host, resource_path=self.path,
            published_revision=head.published_revision,
            attempt_sequence=head.attempt_sequence,
            cohort=self.cohort, observer_key_id=self.observer_key_id,
            expected_sha256=head.content_sha256,
            observed_sha256=observed,
            expected_profile_sha256=head.delivery_profile_sha256,
            observed_profile_sha256=profile_hash,
            http_status=observed_status, complete_bytes=complete,
            measured_at=measured_at, signed_at=self.clock(),
        )
        return self.signer.sign(body)
