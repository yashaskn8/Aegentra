"""Separate artifact-verifier signing purpose for exact staged bytes.

This verifies a pinned external signer; it does not independently fetch bytes,
prove custody or grant publication. The host supplying the public key must be
outside the ordinary API deployment and pinned at enrollment.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import UUID

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field

from aegentra.review_crypto import ReviewSubject, ReviewRejected

HEXDIGEST = r"^[0-9a-f]{64}$"


class StagingProof(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["aegentra.release.staging-proof.v1"]
    audience: Literal["aegentra-authority-redeem"]
    incarnation: UUID
    org_id: UUID
    target_id: UUID
    subject_sha256: str = Field(pattern=HEXDIGEST)
    content_sha256: str = Field(pattern=HEXDIGEST)
    storage_sha256: str = Field(pattern=HEXDIGEST)
    delivery_profile_sha256: str = Field(pattern=HEXDIGEST)
    prior_published_revision: int = Field(ge=0, strict=True)
    verifier_key_id: str = Field(min_length=3, max_length=128)
    issued_at: datetime
    expires_at: datetime

    def canonical(self) -> bytes:
        return rfc8785.dumps(self.model_dump(mode="json"))


def stage_message(proof: StagingProof) -> bytes:
    return b"aegentra.release.staging.signature.v1\x00" + proof.canonical()


def verify_staging_proof(
    *,
    proof: StagingProof,
    signature: bytes,
    public_key: bytes,
    expected_key_id: str,
    subject: ReviewSubject,
    now: datetime,
) -> str:
    if (
        proof.verifier_key_id != expected_key_id
        or proof.org_id != subject.org_id
        or proof.target_id != subject.target_id
        or proof.incarnation != subject.incarnation
        or proof.subject_sha256 != subject.digest()
        or proof.content_sha256 != subject.content_sha256
        or proof.storage_sha256 != subject.storage_sha256
        or proof.delivery_profile_sha256 != subject.delivery_profile_sha256
        or proof.prior_published_revision != subject.prior_published_revision
    ):
        raise ReviewRejected("staging proof does not match approved subject")
    if now.tzinfo is None or proof.issued_at.tzinfo is None or proof.expires_at.tzinfo is None:
        raise ReviewRejected("trusted UTC clock required")
    now = now.astimezone(timezone.utc)
    issue = proof.issued_at.astimezone(timezone.utc)
    expiry = proof.expires_at.astimezone(timezone.utc)
    if issue > now + timedelta(seconds=30) or not issue <= now < expiry:
        raise ReviewRejected("expired or future staging proof")
    if expiry - issue > timedelta(minutes=5):
        raise ReviewRejected("staging proof too long-lived")
    if len(public_key) != 32 or len(signature) != 64:
        raise ReviewRejected("invalid independent verifier key")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, stage_message(proof)
        )
    except (InvalidSignature, ValueError) as exc:
        raise ReviewRejected("independent staging signature rejected") from exc
    return hashlib.sha256(
        b"aegentra.release.staging-record.v1\x00"
        + proof.canonical() + signature
    ).hexdigest()
