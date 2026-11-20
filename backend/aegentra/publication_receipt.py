"""Signed, immutable publication receipt, separate from the witness.

The authority's publication receipt references the previously verified
security-account witness. It never supersedes or fabricates a witness.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import BaseModel, ConfigDict, Field

from aegentra.db import ReleasePublication
from aegentra.review_crypto import ReviewRejected

_HEX = r"^[0-9a-f]{64}$"


class PublicationReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["aegentra.release.publication-receipt.v1"]
    audience: Literal["aegentra-primary-head-authority"]
    org_id: UUID
    target_id: UUID
    incarnation: UUID
    published_revision: int = Field(strict=True, gt=0)
    attempt_sequence: int = Field(strict=True, gt=0)
    witness_sha256: str = Field(pattern=_HEX)
    representation_sha256: str = Field(pattern=_HEX)
    delivery_profile_sha256: str = Field(pattern=_HEX)
    fixed_bundle_sha256: str = Field(pattern=_HEX)
    origin_bucket: str = Field(min_length=3, max_length=63)
    origin_key: str = Field(min_length=1, max_length=256)
    origin_version_id: str = Field(min_length=1, max_length=256)
    signer_key_id: str = Field(min_length=3, max_length=128)
    issued_at: datetime

    def canonical(self) -> bytes:
        return rfc8785.dumps(self.model_dump(mode="json"))


def publication_receipt_message(body: PublicationReceipt) -> bytes:
    return b"aegentra.release.publication-receipt.signature.v1\x00" + body.canonical()


def signed_publication_receipt_bytes(body: PublicationReceipt, signature_der: bytes) -> bytes:
    if not 8 <= len(signature_der) <= 128:
        raise ReviewRejected("invalid publication receipt signature")
    return rfc8785.dumps({
        "body": body.model_dump(mode="json"),
        "signature_der_hex": signature_der.hex(),
    })


def verify_publication_receipt(
    *,
    body: PublicationReceipt, signature_der: bytes,
    pinned_public_der: bytes, expected_key_id: str,
    publication: ReleasePublication, incarnation: UUID,
    now: datetime,
) -> str:
    if (
        body.signer_key_id != expected_key_id
        or body.org_id != publication.org_id
        or body.target_id != publication.target_id
        or body.incarnation != incarnation
        or body.published_revision != publication.published_revision
        or body.attempt_sequence != publication.attempt_sequence
        or body.witness_sha256 != publication.witness_sha256.hex()
        or body.representation_sha256 != publication.representation_sha256.hex()
        or body.delivery_profile_sha256 != publication.delivery_profile_sha256.hex()
        or publication.fixed_bundle_sha256 is None
        or body.fixed_bundle_sha256 != publication.fixed_bundle_sha256.hex()
        or body.origin_bucket != publication.origin_bucket
        or body.origin_key != publication.origin_key
        or body.origin_version_id != publication.origin_version_id
    ):
        raise ReviewRejected("publication receipt does not match committed revision")
    if now.tzinfo is None or body.issued_at.tzinfo is None:
        raise ReviewRejected("trusted UTC clock unavailable")
    issued = body.issued_at.astimezone(timezone.utc)
    if issued < publication.created_at.astimezone(timezone.utc):
        raise ReviewRejected("publication receipt predates commit intent")
    if issued > now.astimezone(timezone.utc):
        raise ReviewRejected("publication receipt issued in future")
    try:
        key = serialization.load_der_public_key(pinned_public_der)
        if (
            not isinstance(key, ec.EllipticCurvePublicKey)
            or not isinstance(key.curve, ec.SECP256R1)
        ):
            raise ReviewRejected("unexpected publication key type")
        key.verify(
            signature_der, publication_receipt_message(body),
            ec.ECDSA(hashes.SHA256()),
        )
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise ReviewRejected("publication receipt signature invalid") from exc
    return hashlib.sha256(signed_publication_receipt_bytes(body, signature_der)).hexdigest()
