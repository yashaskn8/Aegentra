"""Independently verified review subjects and two-person endorsements.

This module verifies enrolled signing keys; it never enrolls keys, issues a
hardware credential or grants publication authority. The enrollment authority
must verify hardware-backed, user-verified credentials in a separate custody
domain before providing ReviewerCredential records.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import UUID

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, model_validator


class ReviewRejected(ValueError):
    pass


_HEX = r"^[0-9a-f]{64}$"
_TOKEN = r"^[A-Za-z0-9_-]{22,128}$"


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ReviewRejected("UTC-aware trusted time is mandatory")
    return value.astimezone(timezone.utc)


def tagged_hash(domain: str, body: bytes) -> str:
    if not domain.startswith("aegentra.") or not domain.isascii():
        raise ReviewRejected("unknown signing domain")
    return hashlib.sha256(domain.encode("ascii") + b"\x00" + body).hexdigest()


class ReviewSubject(BaseModel):
    """Fixed content only; never includes endorsements or grant/witness tokens."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["aegentra.review.subject.v1"]
    incarnation: UUID
    org_id: UUID
    asset_id: UUID
    target_id: UUID
    destination_host: str = Field(min_length=3, max_length=253, pattern=r"^[a-z0-9.-]+$")
    resource_path: str = Field(min_length=1, max_length=160, pattern=r"^/[A-Za-z0-9_.-]*$")
    content_sha256: str = Field(pattern=_HEX)
    storage_sha256: str = Field(pattern=_HEX)
    independent_bytes_sha256: str = Field(pattern=_HEX)
    delivery_profile_sha256: str = Field(pattern=_HEX)
    policy_sha256: str = Field(pattern=_HEX)
    baseline_sha256: str = Field(pattern=_HEX)
    source_attestation_sha256: str = Field(pattern=_HEX)
    scan_receipt_sha256: str = Field(pattern=_HEX)
    change_request_sha256: str = Field(pattern=_HEX)
    baseline_revision: int = Field(ge=0, strict=True)
    prior_published_revision: int = Field(ge=0, strict=True)
    org_epoch: int = Field(ge=1, strict=True)
    target_epoch: int = Field(ge=1, strict=True)
    submitter_person_id: UUID

    @model_validator(mode="after")
    def byte_proofs_agree(self) -> "ReviewSubject":
        # Independent acquisition must match the exact uploaded final bytes.
        if self.content_sha256 != self.independent_bytes_sha256:
            raise ValueError("independent final-byte proof differs from intended content")
        return self

    def canonical(self) -> bytes:
        return rfc8785.dumps(self.model_dump(mode="json"))

    def digest(self) -> str:
        return tagged_hash("aegentra.review.subject.v1", self.canonical())


class EndorsementBody(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["aegentra.review.endorsement.v1"]
    subject_sha256: str = Field(pattern=_HEX)
    person_id: UUID
    key_id: str = Field(min_length=3, max_length=128)
    custody_group: str = Field(min_length=3, max_length=64)
    challenge_nonce: str = Field(min_length=22, max_length=128, pattern=_TOKEN)
    enrollment_generation: int = Field(ge=1, strict=True)
    audience: Literal["aegentra-independent-review"]
    action: Literal["ENDORSE_FINAL_BYTES"]
    issued_at: datetime
    expires_at: datetime

    def canonical(self) -> bytes:
        return rfc8785.dumps(self.model_dump(mode="json"))


@dataclass(frozen=True)
class ReviewerCredential:
    person_id: UUID
    key_id: str
    custody_group: str
    enrollment_generation: int
    public_ed25519: bytes
    independently_verified: bool
    active: bool = True


@dataclass(frozen=True)
class SignedEndorsement:
    body: EndorsementBody
    signature: bytes


@dataclass(frozen=True)
class ApprovalSet:
    subject_sha256: str
    approval_set_sha256: str
    people: tuple[UUID, UUID]
    groups: tuple[str, str]


def endorsement_message(body: EndorsementBody) -> bytes:
    return b"aegentra.review.endorsement.signature.v1\x00" + body.canonical()


def verify_approval_set(
    *,
    subject: ReviewSubject,
    endorsements: tuple[SignedEndorsement, SignedEndorsement],
    enrolled: dict[str, ReviewerCredential],
    used_challenges: frozenset[str],
    now: datetime,
) -> ApprovalSet:
    """Verify exactly two independent signers against an external enrollment snapshot.

    Challenge consumption must be persisted in a separate serialized authority
    transaction. A local set is not a replay ledger and must never replace it.
    """
    trusted_now = _utc(now)
    digest = subject.digest()
    people: set[UUID] = set()
    groups: set[str] = set()
    keys: set[str] = set()
    challenges: set[str] = set()
    signed_bodies: list[bytes] = []
    if len(endorsements) != 2:
        raise ReviewRejected("exactly two endorsements required")

    for endorsement in endorsements:
        body = endorsement.body
        credential = enrolled.get(body.key_id)
        if (
            credential is None or not credential.active
            or not credential.independently_verified
            or credential.person_id != body.person_id
            or credential.key_id != body.key_id
            or credential.custody_group != body.custody_group
            or credential.enrollment_generation != body.enrollment_generation
            or len(credential.public_ed25519) != 32
        ):
            raise ReviewRejected("unqualified or mismatched reviewer enrollment")
        if (
            body.subject_sha256 != digest
            or body.person_id == subject.submitter_person_id
            or body.person_id in people
            or body.custody_group in groups
            or body.key_id in keys
            or body.challenge_nonce in challenges
            or body.challenge_nonce in used_challenges
        ):
            raise ReviewRejected("review independence, identity or replay violation")

        issue, expiry = _utc(body.issued_at), _utc(body.expires_at)
        if (
            issue > trusted_now + timedelta(seconds=30)
            or expiry <= trusted_now
            or expiry - issue > timedelta(minutes=5)
            or trusted_now < issue - timedelta(seconds=30)
        ):
            raise ReviewRejected("expired or implausible endorsement window")

        try:
            Ed25519PublicKey.from_public_bytes(credential.public_ed25519).verify(
                endorsement.signature, endorsement_message(body)
            )
        except (InvalidSignature, ValueError) as exc:
            raise ReviewRejected("reviewer signature invalid") from exc

        people.add(body.person_id)
        groups.add(body.custody_group)
        keys.add(body.key_id)
        challenges.add(body.challenge_nonce)
        signed_bodies.append(rfc8785.dumps({
            "body": body.model_dump(mode="json"),
            "signature": endorsement.signature.hex(),
        }))

    ordered = sorted(signed_bodies)
    approval_hash = tagged_hash(
        "aegentra.review.approval-set.v1",
        rfc8785.dumps({"subject_sha256": digest, "endorsements": [
            # Canonical endorsement objects sorted by full serialized bytes.
            __import__("json").loads(item) for item in ordered
        ]}),
    )
    return ApprovalSet(
        subject_sha256=digest,
        approval_set_sha256=approval_hash,
        people=tuple(sorted(people, key=str)),
        groups=tuple(sorted(groups)),
    )
