"""Typed, nonce-bound published-head and independent veto snapshots.

These signatures identify statements from independently configured principals;
the gateway must fetch both live for *every* admission and never cache current
root/veto state. An immutable witness certificate is separately required.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import UUID

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import BaseModel, ConfigDict, Field, model_validator


class AdmissionDenied(ValueError):
    """No protected response bytes may leave the gateway."""


_SHA = r"^[0-9a-f]{64}$"
_NONCE = r"^[A-Za-z0-9_-]{43}$"


class HeadSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["aegentra.authority.head.v1"]
    audience: Literal["aegentra-protected-gateway"]
    request_nonce: str = Field(pattern=_NONCE)
    incarnation: UUID
    org_id: UUID
    target_id: UUID
    destination_host: str = Field(min_length=3, max_length=253, pattern=r"^[a-z0-9.-]+$")
    resource_path: str = Field(min_length=1, max_length=160, pattern=r"^/[A-Za-z0-9_.-]*$")
    mode: Literal["SHADOW", "ENFORCED", "RETIRED"]
    guard: Literal["ACTIVE", "HOLD_PROMOTION", "STOP_SERVING"]
    published_revision: int = Field(strict=True, ge=0)
    attempt_sequence: int = Field(strict=True, ge=0)
    content_sha256: str = Field(pattern=_SHA)
    delivery_profile_sha256: str = Field(pattern=_SHA)
    fixed_bundle_sha256: str = Field(pattern=_SHA)
    witness_bucket: str = Field(min_length=3, max_length=63)
    witness_key: str = Field(min_length=1, max_length=256)
    witness_version_id: str = Field(min_length=1, max_length=256)
    witness_sha256: str = Field(pattern=_SHA)
    origin_bucket: str = Field(min_length=3, max_length=63)
    origin_key: str = Field(min_length=1, max_length=256)
    origin_version_id: str = Field(min_length=1, max_length=256)
    issued_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def bounded(self) -> "HeadSnapshot":
        if (
            self.issued_at.tzinfo is None or self.expires_at.tzinfo is None
            or not self.issued_at < self.expires_at
            or self.expires_at - self.issued_at > timedelta(seconds=2)
        ):
            raise ValueError("head response must expire within two seconds")
        return self

    def canonical(self) -> bytes:
        return rfc8785.dumps(self.model_dump(mode="json"))


class VetoSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["aegentra.security.veto-state.v1"]
    audience: Literal["aegentra-protected-gateway"]
    request_nonce: str = Field(pattern=_NONCE)
    org_id: UUID
    incarnation: UUID
    root_generation: int = Field(strict=True, gt=0)
    veto_generation: int = Field(strict=True, ge=0)
    state: Literal["CLEAR", "STOP"]
    issued_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def bounded(self) -> "VetoSnapshot":
        if (
            self.issued_at.tzinfo is None or self.expires_at.tzinfo is None
            or not self.issued_at < self.expires_at
            or self.expires_at - self.issued_at > timedelta(seconds=2)
        ):
            raise ValueError("veto response must expire within two seconds")
        return self

    def canonical(self) -> bytes:
        return rfc8785.dumps(self.model_dump(mode="json"))


@dataclass(frozen=True)
class SignedHead:
    body: HeadSnapshot
    signature_der: bytes


@dataclass(frozen=True)
class SignedVeto:
    body: VetoSnapshot
    signature_der: bytes


def head_message(body: HeadSnapshot) -> bytes:
    return b"aegentra.authority.head.signature.v1\x00" + body.canonical()


def veto_message(body: VetoSnapshot) -> bytes:
    return b"aegentra.security.veto.signature.v1\x00" + body.canonical()


def _verify_pinned_key(public_key_der: bytes, signature_der: bytes, message: bytes) -> None:
    if not 8 <= len(signature_der) <= 128:
        raise AdmissionDenied("invalid signed snapshot")
    try:
        key = serialization.load_der_public_key(public_key_der)
        if (
            not isinstance(key, ec.EllipticCurvePublicKey)
            or not isinstance(key.curve, ec.SECP256R1)
        ):
            raise AdmissionDenied("unexpected gateway verification key type")
        key.verify(signature_der, message, ec.ECDSA(hashes.SHA256()))
    except (TypeError, ValueError, InvalidSignature) as exc:
        raise AdmissionDenied("signed snapshot verification failed") from exc


def _fresh(issue: datetime, expiry: datetime, now: datetime) -> None:
    if now.tzinfo is None or now.utcoffset() is None:
        raise AdmissionDenied("trusted gateway clock unavailable")
    trusted = now.astimezone(timezone.utc)
    if issue.astimezone(timezone.utc) > trusted + timedelta(milliseconds=300):
        raise AdmissionDenied("snapshot issued in the future")
    if trusted >= expiry.astimezone(timezone.utc):
        raise AdmissionDenied("snapshot is expired")


def verify_head(
    envelope: SignedHead, *,
    pinned_key_der: bytes, nonce: str,
    org_id: UUID, target_id: UUID, incarnation: UUID,
    host: str, path: str, now: datetime,
) -> HeadSnapshot:
    body = envelope.body
    _verify_pinned_key(pinned_key_der, envelope.signature_der, head_message(body))
    _fresh(body.issued_at, body.expires_at, now)
    if (
        body.request_nonce != nonce
        or body.org_id != org_id or body.target_id != target_id
        or body.incarnation != incarnation
        or body.destination_host != host or body.resource_path != path
        or body.mode != "ENFORCED" or body.guard == "STOP_SERVING"
        or body.published_revision < 1 or body.attempt_sequence < 1
        or body.witness_version_id == "null" or body.origin_version_id == "null"
    ):
        raise AdmissionDenied("published authority head does not authorize target")
    return body


def verify_veto(
    envelope: SignedVeto, *, pinned_key_der: bytes,
    nonce: str, org_id: UUID, incarnation: UUID, now: datetime,
    minimum_root_generation: int,
) -> VetoSnapshot:
    body = envelope.body
    _verify_pinned_key(pinned_key_der, envelope.signature_der, veto_message(body))
    _fresh(body.issued_at, body.expires_at, now)
    if (
        body.request_nonce != nonce or body.org_id != org_id
        or body.incarnation != incarnation
        or body.root_generation < minimum_root_generation
        or body.state != "CLEAR"
    ):
        raise AdmissionDenied("live independent security veto blocks admission")
    return body
