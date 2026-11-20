"""Independently signed binding of published origin bytes to an exact S3 version.

An artifact verifier must rehash the full source body outside the authority
transaction using independent credentials before issuing this statement.
The authority verifies the signature but does not infer byte provenance from
the signature alone; signing infrastructure qualification is a separate P0.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import UUID

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import BaseModel, ConfigDict, Field

from aegentra.review_crypto import ReviewRejected, ReviewSubject
from aegentra.origin_scope import origin_key_in_scope

_HEX = r"^[0-9a-f]{64}$"


class OriginBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["aegentra.independent.origin-binding.v1"]
    audience: Literal["aegentra-publication-authority"]
    incarnation: UUID
    org_id: UUID
    target_id: UUID
    subject_sha256: str = Field(pattern=_HEX)
    destination_host: str = Field(min_length=3, max_length=253)
    resource_path: str = Field(min_length=1, max_length=160)
    origin_bucket: str = Field(min_length=3, max_length=63)
    origin_key: str = Field(min_length=1, max_length=256)
    origin_version_id: str = Field(min_length=1, max_length=256)
    content_sha256: str = Field(pattern=_HEX)
    delivery_profile_sha256: str = Field(pattern=_HEX)
    fixed_bundle_sha256: str = Field(pattern=_HEX)
    signer_key_id: str = Field(min_length=3, max_length=128)
    issued_at: datetime
    expires_at: datetime

    def canonical(self) -> bytes:
        return rfc8785.dumps(self.model_dump(mode="json"))


def origin_message(binding: OriginBinding) -> bytes:
    return b"aegentra.independent.origin-binding.signature.v1\x00" + binding.canonical()


def verify_origin_binding(
    *,
    binding: OriginBinding, signature_der: bytes,
    pinned_verifier_der: bytes, expected_key_id: str,
    subject: ReviewSubject, enrolled_bucket: str,
    enrolled_key_prefix: str, now: datetime,
) -> None:
    if (
        binding.signer_key_id != expected_key_id
        or binding.incarnation != subject.incarnation
        or binding.org_id != subject.org_id
        or binding.target_id != subject.target_id
        or binding.subject_sha256 != subject.digest()
        or binding.destination_host != subject.destination_host
        or binding.resource_path != subject.resource_path
        or binding.content_sha256 != subject.content_sha256
        or binding.delivery_profile_sha256 != subject.delivery_profile_sha256
        or binding.fixed_bundle_sha256 != subject.fixed_bundle_sha256
        or binding.origin_bucket != enrolled_bucket
        or not origin_key_in_scope(enrolled_key_prefix, binding.origin_key)
        or binding.origin_version_id == "null"
    ):
        raise ReviewRejected("signed origin bytes are outside enrolled target")
    if (
        now.tzinfo is None or binding.issued_at.tzinfo is None
        or binding.expires_at.tzinfo is None
    ):
        raise ReviewRejected("trusted authority clock unavailable")
    now = now.astimezone(timezone.utc)
    issued = binding.issued_at.astimezone(timezone.utc)
    expires = binding.expires_at.astimezone(timezone.utc)
    if (
        issued > now + timedelta(seconds=30)
        or now < issued - timedelta(seconds=30)
        or expires <= now or expires - issued > timedelta(minutes=5)
    ):
        raise ReviewRejected("origin binding expired or issued in future")
    try:
        key = serialization.load_der_public_key(pinned_verifier_der)
        if (
            not isinstance(key, ec.EllipticCurvePublicKey)
            or not isinstance(key.curve, ec.SECP256R1)
        ):
            raise ReviewRejected("unexpected origin verifier key")
        key.verify(signature_der, origin_message(binding), ec.ECDSA(hashes.SHA256()))
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise ReviewRejected("origin binding signature invalid") from exc
