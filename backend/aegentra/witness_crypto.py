"""Independent security-account witness certificate, not a publication token.

Production signing keys must reside in separately administered AWS KMS and
may never be accessible to the API, release authority or origin gateway.
Verification uses a pinned external P-256 public key with domain separation.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import BaseModel, ConfigDict, Field, model_validator


class WitnessRejected(ValueError):
    pass


_HEX = r"^[0-9a-f]{64}$"


class WitnessBody(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["aegentra.security.witness.v1"]
    audience: Literal["aegentra-release-publication"]
    incarnation: UUID
    org_id: UUID
    target_id: UUID
    attempt_sequence: int = Field(strict=True, gt=0)
    prior_published_revision: int = Field(strict=True, ge=0)
    predecessor_witness_sha256: str = Field(pattern=_HEX)
    subject_sha256: str = Field(pattern=_HEX)
    approval_set_sha256: str = Field(pattern=_HEX)
    staging_sha256: str = Field(pattern=_HEX)
    content_sha256: str = Field(pattern=_HEX)
    delivery_profile_sha256: str = Field(pattern=_HEX)
    fixed_bundle_sha256: str = Field(pattern=_HEX)
    security_root_generation: int = Field(strict=True, gt=0)
    selection_deadline: datetime
    issued_at: datetime

    @model_validator(mode="after")
    def chronological(self) -> "WitnessBody":
        if self.selection_deadline.tzinfo is None or self.issued_at.tzinfo is None:
            raise ValueError("witness dates must include a timezone")
        if self.issued_at > self.selection_deadline:
            raise ValueError("witness issued after selection deadline")
        return self

    def canonical(self) -> bytes:
        return rfc8785.dumps(self.model_dump(mode="json"))


@dataclass(frozen=True)
class WitnessSelection:
    org_id: UUID
    target_id: UUID
    attempt_sequence: int
    prior_published_revision: int
    subject_sha256: str
    approval_set_sha256: str
    staging_sha256: str
    content_sha256: str
    delivery_profile_sha256: str
    fixed_bundle_sha256: str
    predecessor_witness_sha256: str
    selected_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class WitnessArchiveRef:
    bucket: str
    key: str
    version_id: str
    object_sha256: str


def witness_message(body: WitnessBody) -> bytes:
    return b"aegentra.security.witness.signature.v1\x00" + body.canonical()


def signed_certificate_bytes(body: WitnessBody, signature: bytes) -> bytes:
    if not 8 <= len(signature) <= 128:
        raise WitnessRejected("invalid witness DER signature length")
    return rfc8785.dumps({
        "body": body.model_dump(mode="json"),
        "signature_der_hex": signature.hex(),
    })


def verify_witness_certificate(
    *,
    body: WitnessBody, signature: bytes,
    pinned_public_key_der: bytes,
    selection: WitnessSelection,
    incarnation: UUID,
    root_generation: int,
    no_external_veto: bool,
    now: datetime,
) -> str:
    """Return immutable certificate object digest, never a serve/allow verdict."""
    if not no_external_veto:
        raise WitnessRejected("independent security-account STOP present")
    if now.tzinfo is None or now.utcoffset() is None:
        raise WitnessRejected("fresh trusted clock unavailable")
    if (
        body.incarnation != incarnation
        or body.security_root_generation != root_generation
        or body.org_id != selection.org_id
        or body.target_id != selection.target_id
        or body.attempt_sequence != selection.attempt_sequence
        or body.prior_published_revision != selection.prior_published_revision
        or body.subject_sha256 != selection.subject_sha256
        or body.approval_set_sha256 != selection.approval_set_sha256
        or body.staging_sha256 != selection.staging_sha256
        or body.content_sha256 != selection.content_sha256
        or body.delivery_profile_sha256 != selection.delivery_profile_sha256
        or body.fixed_bundle_sha256 != selection.fixed_bundle_sha256
        or body.predecessor_witness_sha256 != selection.predecessor_witness_sha256
        or body.selection_deadline != selection.expires_at
        or body.issued_at < selection.selected_at
        or body.issued_at > now.astimezone(timezone.utc)
        or now.astimezone(timezone.utc) >= selection.expires_at
    ):
        raise WitnessRejected("witness does not match current committed selection")

    try:
        public = serialization.load_der_public_key(pinned_public_key_der)
        if (
            not isinstance(public, ec.EllipticCurvePublicKey)
            or not isinstance(public.curve, ec.SECP256R1)
        ):
            raise WitnessRejected("witness requires a pinned P-256 verification key")
        public.verify(signature, witness_message(body), ec.ECDSA(hashes.SHA256()))
    except (ValueError, InvalidSignature, TypeError) as exc:
        raise WitnessRejected("witness signature untrusted") from exc
    return hashlib.sha256(signed_certificate_bytes(body, signature)).hexdigest()
