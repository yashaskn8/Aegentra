"""Independent two-object fixed-browser bundle verification contract.

No submitted code is imported or executed. A separately credentialed verifier
must obtain original bytes from exact versioned storage, and use a distinct
signing purpose. This module does not grant or publish a release.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal, Protocol
from uuid import UUID

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import BaseModel, ConfigDict, Field

from aegentra.evidence_verifier import (
    EvidenceMismatch, VersionedBlobReader, verify_versioned_blob,
)
from aegentra.fixed_delivery import FixedStaticProfile, UnsupportedDelivery

_SHA = r"^[0-9a-f]{64}$"
_KEY = re.compile(r"published/[A-Za-z0-9/_.-]{1,240}\Z")


class BundleRejected(ValueError):
    pass


class PinnedOriginObject(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    bucket: str = Field(min_length=3, max_length=63, pattern=r"^[a-z0-9.-]+$")
    key: str = Field(min_length=10, max_length=256)
    version_id: str = Field(min_length=1, max_length=256)

    def check(self, *, bucket: str, prefix: str) -> None:
        if (
            self.bucket != bucket or self.version_id == "null"
            or self.key.startswith("/") or ".." in self.key.split("/")
            or not _KEY.fullmatch(self.key)
            or not self.key.startswith(prefix)
            or not prefix.startswith("published/")
        ):
            raise BundleRejected("origin object outside pinned immutable namespace")


@dataclass(frozen=True)
class VerifiedFixedBundle:
    profile: FixedStaticProfile
    entry: PinnedOriginObject
    script: PinnedOriginObject
    bundle_manifest_sha256: str
    storage_manifest_sha256: str

    def source_identity(self) -> str:
        return hashlib.sha256(
            b"aegentra.fixed-bundle.source-identity.v1\x00"
            + rfc8785.dumps({
                "bundle_manifest_sha256": self.bundle_manifest_sha256,
                "storage_manifest_sha256": self.storage_manifest_sha256,
            })
        ).hexdigest()


def verify_fixed_bundle_versions(
    *,
    profile: FixedStaticProfile,
    entry: PinnedOriginObject, script: PinnedOriginObject,
    pinned_bucket: str, pinned_prefix: str,
    entry_reader: VersionedBlobReader, script_reader: VersionedBlobReader,
) -> VerifiedFixedBundle:
    """Independently rehash both exact S3 versions before signing any facts."""
    entry.check(bucket=pinned_bucket, prefix=pinned_prefix)
    script.check(bucket=pinned_bucket, prefix=pinned_prefix)
    if entry.key == script.key:
        raise BundleRejected("entry and script must be distinct immutable objects")
    if not isinstance(profile, FixedStaticProfile):
        raise BundleRejected("unqualified delivery template")
    html = profile.generated_html()
    try:
        verify_versioned_blob(
            reader=entry_reader, version_id=entry.version_id,
            expected_sha256=hashlib.sha256(html).hexdigest(),
            expected_length=len(html),
        )
        verify_versioned_blob(
            reader=script_reader, version_id=script.version_id,
            expected_sha256=profile.script_sha256,
            expected_length=profile.script_length,
        )
    except EvidenceMismatch as exc:
        raise BundleRejected("missing or altered versioned bundle content") from exc

    manifest_sha = profile.manifest_sha256()
    storage_sha = hashlib.sha256(
        b"aegentra.fixed-bundle.storage.v1\x00"
        + rfc8785.dumps({
            "kind": "aegentra.fixed-bundle.storage.v1",
            "bundle_manifest_sha256": manifest_sha,
            "entry": entry.model_dump(mode="json"),
            "script": script.model_dump(mode="json"),
        })
    ).hexdigest()
    return VerifiedFixedBundle(
        profile=profile, entry=entry, script=script,
        bundle_manifest_sha256=manifest_sha,
        storage_manifest_sha256=storage_sha,
    )


class FixedBundleAttestation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["aegentra.independent.fixed-bundle.v1"]
    audience: Literal["aegentra-release-review"]
    org_id: UUID
    target_id: UUID
    incarnation: UUID
    host: str = Field(min_length=3, max_length=253)
    template_version: Literal["aegentra-fixed-entry-v1"]
    entry_path: Literal["/index.html"]
    script_path: str = Field(min_length=10, max_length=100)
    entry_sha256: str = Field(pattern=_SHA)
    script_sha256: str = Field(pattern=_SHA)
    script_length: int = Field(strict=True, gt=0, le=1024 * 1024)
    bundle_manifest_sha256: str = Field(pattern=_SHA)
    storage_manifest_sha256: str = Field(pattern=_SHA)
    entry: PinnedOriginObject
    script: PinnedOriginObject
    verifier_key_id: str = Field(min_length=3, max_length=128)
    issued_at: datetime
    expires_at: datetime

    def canonical(self) -> bytes:
        return rfc8785.dumps(self.model_dump(mode="json"))


def bundle_message(body: FixedBundleAttestation) -> bytes:
    return b"aegentra.independent.fixed-bundle.signature.v1\x00" + body.canonical()


def verify_fixed_bundle_attestation(
    *, body: FixedBundleAttestation, signature_der: bytes,
    verified: VerifiedFixedBundle,
    public_key_der: bytes, expected_key_id: str,
    org_id: UUID, target_id: UUID, incarnation: UUID, now: datetime,
) -> str:
    """Pin signed claim to independently recomputed EXACT storage+content facts."""
    profile = verified.profile
    if (
        body.org_id != org_id or body.target_id != target_id
        or body.incarnation != incarnation or body.host != profile.host
        or body.template_version != profile.template_version
        or body.entry_path != profile.entry_path
        or body.script_path != profile.script_path
        or body.entry_sha256 != hashlib.sha256(profile.generated_html()).hexdigest()
        or body.script_sha256 != profile.script_sha256
        or body.script_length != profile.script_length
        or body.bundle_manifest_sha256 != verified.bundle_manifest_sha256
        or body.storage_manifest_sha256 != verified.storage_manifest_sha256
        or body.entry != verified.entry or body.script != verified.script
        or body.verifier_key_id != expected_key_id
    ):
        raise BundleRejected("independent bundle proof differs from verified versions")
    if (
        now.tzinfo is None or body.issued_at.tzinfo is None
        or body.expires_at.tzinfo is None
    ):
        raise BundleRejected("trusted UTC clock required")
    n = now.astimezone(timezone.utc)
    issued, expiry = (
        body.issued_at.astimezone(timezone.utc),
        body.expires_at.astimezone(timezone.utc),
    )
    if (
        issued > n + timedelta(seconds=30)
        or not issued <= n < expiry
        or expiry - issued > timedelta(minutes=5)
    ):
        raise BundleRejected("bundle attestation outside trusted validity window")
    if not 8 <= len(signature_der) <= 128:
        raise BundleRejected("invalid bundle signature length")
    try:
        key = serialization.load_der_public_key(public_key_der)
        if (
            not isinstance(key, ec.EllipticCurvePublicKey)
            or not isinstance(key.curve, ec.SECP256R1)
        ):
            raise BundleRejected("wrong independent signing algorithm")
        key.verify(signature_der, bundle_message(body), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise BundleRejected("independent bundle signature invalid") from exc
    return hashlib.sha256(
        b"aegentra.independent.fixed-bundle.record.v1\x00"
        + rfc8785.dumps({
            "body": body.model_dump(mode="json"),
            "signature_der_hex": signature_der.hex(),
        })
    ).hexdigest()


def verify_review_subject_bundle(
    *, subject: "ReviewSubject", body: FixedBundleAttestation,
    signature_der: bytes, verified: VerifiedFixedBundle,
    pinned_verifier_public_der: bytes, expected_verifier_key_id: str,
    now: datetime,
) -> str:
    """Bind an immutable review subject to independently rehashed HTML+JS.

    The protected reference subject identifies the fixed HTML entry and
    includes the two-object manifest via its separately signed source proof.
    A separate per-resource script head is still required for actual serving.
    """
    from aegentra.review_crypto import ReviewSubject

    if not isinstance(subject, ReviewSubject):
        raise BundleRejected("review subject type invalid")
    attestation_digest = verify_fixed_bundle_attestation(
        body=body, signature_der=signature_der, verified=verified,
        public_key_der=pinned_verifier_public_der,
        expected_key_id=expected_verifier_key_id,
        org_id=subject.org_id, target_id=subject.target_id,
        incarnation=subject.incarnation, now=now,
    )
    html = verified.profile.generated_html()
    html_digest = hashlib.sha256(html).hexdigest()
    header_digest = hashlib.sha256(
        b"aegentra.delivery.profile.v1\x00"
        + rfc8785.dumps(verified.profile.headers(
            path=verified.profile.entry_path, content=html,
        ))
    ).hexdigest()
    if (
        subject.destination_host != verified.profile.host
        or subject.resource_path != verified.profile.entry_path
        or subject.content_sha256 != html_digest
        or subject.independent_bytes_sha256 != html_digest
        or subject.delivery_profile_sha256 != header_digest
        or subject.fixed_bundle_sha256 != verified.bundle_manifest_sha256
        or subject.storage_sha256 != verified.storage_manifest_sha256
        or subject.source_attestation_sha256 != attestation_digest
    ):
        raise BundleRejected("review intent not bound to independently signed bundle")
    return attestation_digest
