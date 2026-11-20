"""Independent exact-response observer attestation, never a release approval.

A separately enrolled observer signs a measured client-facing representation.
The authority rechecks the current target and published slot before applying
STOP for a fresh current mismatch. Old mismatches remain historical cases.
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

_HEX = r"^[0-9a-f]{64}$"


class ObservationRejected(ValueError):
    pass


class ObservationBody(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["aegentra.observer.readback.v1"]
    audience: Literal["aegentra-release-observer"]
    observation_id: UUID
    incarnation: UUID
    org_id: UUID
    target_id: UUID
    host: str = Field(min_length=3, max_length=253, pattern=r"^[a-z0-9.-]+$")
    resource_path: str = Field(min_length=1, max_length=160, pattern=r"^/[A-Za-z0-9_.-]*$")
    published_revision: int = Field(strict=True, gt=0)
    attempt_sequence: int = Field(strict=True, gt=0)
    cohort: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
    observer_key_id: str = Field(min_length=3, max_length=128)
    expected_sha256: str = Field(pattern=_HEX)
    observed_sha256: str = Field(pattern=_HEX)
    expected_profile_sha256: str = Field(pattern=_HEX)
    observed_profile_sha256: str = Field(pattern=_HEX)
    http_status: int = Field(strict=True, ge=100, le=599)
    complete_bytes: bool = Field(strict=True)
    measured_at: datetime
    signed_at: datetime

    @model_validator(mode="after")
    def chronological(self) -> "ObservationBody":
        if (
            self.measured_at.tzinfo is None or self.signed_at.tzinfo is None
            or not self.measured_at <= self.signed_at
            or self.signed_at - self.measured_at > timedelta(seconds=30)
        ):
            raise ValueError("observer receipt must be timely and UTC-aware")
        return self

    def canonical(self) -> bytes:
        return rfc8785.dumps(self.model_dump(mode="json"))


@dataclass(frozen=True)
class ObserverCredential:
    key_id: str
    public_key_der: bytes
    independently_enrolled: bool
    active: bool = True


@dataclass(frozen=True)
class SignedObservation:
    body: ObservationBody
    signature_der: bytes


def observation_message(body: ObservationBody) -> bytes:
    return b"aegentra.observer.readback.signature.v1\x00" + body.canonical()


def verify_observation(
    envelope: SignedObservation, *,
    observer: ObserverCredential, now: datetime,
) -> ObservationBody:
    body = envelope.body
    if (
        not observer.independently_enrolled or not observer.active
        or observer.key_id != body.observer_key_id
        or now.tzinfo is None or now.utcoffset() is None
    ):
        raise ObservationRejected("independent observer enrollment unavailable")
    when = now.astimezone(timezone.utc)
    if body.signed_at.astimezone(timezone.utc) > when + timedelta(seconds=30):
        raise ObservationRejected("observer signature issued in future")
    if not 8 <= len(envelope.signature_der) <= 128:
        raise ObservationRejected("malformed observer signature")
    try:
        key = serialization.load_der_public_key(observer.public_key_der)
        if (
            not isinstance(key, ec.EllipticCurvePublicKey)
            or not isinstance(key.curve, ec.SECP256R1)
        ):
            raise ObservationRejected("incorrect observer signing algorithm")
        key.verify(
            envelope.signature_der,
            observation_message(body),
            ec.ECDSA(hashes.SHA256()),
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ObservationRejected("observer signature does not verify") from exc
    return body
