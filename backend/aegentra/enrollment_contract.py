"""S0 independently signed protected-origin enrollment contract.

The fixed profile permits ONE browser entry HTML and ONE same-origin classic
JavaScript resource only. It is a prerequisite, never release authority.
Reviewer, customer and security public keys must be enrolled out of band.
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


class EnrollmentRejected(ValueError):
    pass


_HEX = r"^[0-9a-f]{64}$"
_ACCOUNT = r"^[0-9]{12}$"
_HOST = r"^[a-z0-9.-]{3,253}$"
_PATH = r"^/[a-zA-Z0-9_.-]{1,128}$"


class ProtectedOriginContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["aegentra.enrollment.protected-origin.v1"]
    org_id: UUID
    target_id: UUID
    incarnation: UUID
    destination_host: str = Field(pattern=_HOST)
    html_path: str = Field(pattern=_PATH)
    classic_js_path: str = Field(pattern=_PATH)
    html_max_bytes: int = Field(strict=True, gt=0, le=1024 * 1024)
    js_max_bytes: Literal[1048576]
    origin_bucket: str = Field(min_length=3, max_length=63)
    origin_prefix: str = Field(min_length=11, max_length=160)
    workload_account: str = Field(pattern=_ACCOUNT)
    analysis_account: str = Field(pattern=_ACCOUNT)
    security_account: str = Field(pattern=_ACCOUNT)
    aws_region: str = Field(pattern=r"^[a-z]{2}-[a-z]+-[0-9]$")
    residency_policy_sha256: str = Field(pattern=_HEX)
    incident_policy_sha256: str = Field(pattern=_HEX)
    fixture_oracle_sha256: str = Field(pattern=_HEX)
    delivery_profile_sha256: str = Field(pattern=_HEX)
    outage_behavior: Literal["DENY_PROTECTED_READS"]
    release_mode: Literal["SHADOW_PENDING_INDEPENDENT_QUALIFICATION"]
    max_admission_milliseconds: Literal[2000]
    signed_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def bounded_profile(self) -> "ProtectedOriginContract":
        if (
            self.html_path == self.classic_js_path
            or self.html_path.lower().endswith(".js")
            or not self.classic_js_path.lower().endswith(".js")
            or not self.html_path.lower().endswith(".html")
            or not self.origin_prefix.startswith("published/")
            or not self.origin_prefix.endswith("/")
            or ".." in self.origin_prefix.split("/")
            or len({
                self.workload_account, self.analysis_account, self.security_account
            }) != 3
            or self.signed_at.tzinfo is None
            or self.expires_at.tzinfo is None
            or not self.signed_at < self.expires_at
        ):
            raise ValueError("invalid fixed protected-origin or independent custody profile")
        return self

    def canonical(self) -> bytes:
        return rfc8785.dumps(self.model_dump(mode="json"))

    def digest(self) -> str:
        return hashlib.sha256(
            b"aegentra.enrollment.contract.v1\x00" + self.canonical()
        ).hexdigest()


class OwnerEndorsement(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["aegentra.enrollment.owner-approval.v1"]
    role: Literal["CUSTOMER_ORIGIN_OWNER", "SECURITY_CUSTODIAN"]
    contract_sha256: str = Field(pattern=_HEX)
    person_id: UUID
    key_id: str = Field(min_length=3, max_length=128)
    custody_group: str = Field(min_length=3, max_length=64)
    expires_at: datetime

    def canonical(self) -> bytes:
        return rfc8785.dumps(self.model_dump(mode="json"))


@dataclass(frozen=True)
class EnrolledOwner:
    key_id: str
    person_id: UUID
    custody_group: str
    public_der: bytes
    independently_enrolled: bool
    active: bool


@dataclass(frozen=True)
class SignedOwnerEndorsement:
    body: OwnerEndorsement
    signature_der: bytes


@dataclass(frozen=True)
class FrozenScope:
    contract_sha256: str
    status: Literal["SHADOW_ONLY_INDEPENDENT_QUALIFICATION_REQUIRED"] = (
        "SHADOW_ONLY_INDEPENDENT_QUALIFICATION_REQUIRED"
    )


def owner_message(body: OwnerEndorsement) -> bytes:
    return b"aegentra.enrollment.owner-approval.signature.v1\x00" + body.canonical()


def verify_frozen_scope(
    *, contract: ProtectedOriginContract,
    signatures: tuple[SignedOwnerEndorsement, SignedOwnerEndorsement],
    enrolled_owners: dict[str, EnrolledOwner],
    now: datetime,
) -> FrozenScope:
    if now.tzinfo is None or now.utcoffset() is None:
        raise EnrollmentRejected("trusted UTC custody clock required")
    moment = now.astimezone(timezone.utc)
    if not contract.signed_at <= moment < contract.expires_at:
        raise EnrollmentRejected("scope is not currently effective")
    if len(signatures) != 2:
        raise EnrollmentRejected("two independent owner signatures required")
    roles: set[str] = set()
    people: set[UUID] = set()
    groups: set[str] = set()
    keys: set[str] = set()
    for signed in signatures:
        body = signed.body
        credential = enrolled_owners.get(body.key_id)
        if (
            credential is None or not credential.active
            or not credential.independently_enrolled
            or credential.person_id != body.person_id
            or credential.key_id != body.key_id
            or credential.custody_group != body.custody_group
            or body.contract_sha256 != contract.digest()
            or body.role in roles
            or body.person_id in people
            or body.key_id in keys
            or body.custody_group in groups
            or body.expires_at.tzinfo is None
            or moment >= body.expires_at.astimezone(timezone.utc)
        ):
            raise EnrollmentRejected("owner signature is stale or lacks custody separation")
        try:
            public = serialization.load_der_public_key(credential.public_der)
            if (
                not isinstance(public, ec.EllipticCurvePublicKey)
                or not isinstance(public.curve, ec.SECP256R1)
                or not 8 <= len(signed.signature_der) <= 128
            ):
                raise EnrollmentRejected("unexpected signing algorithm")
            public.verify(
                signed.signature_der,
                owner_message(body),
                ec.ECDSA(hashes.SHA256()),
            )
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise EnrollmentRejected("invalid scope owner signature") from exc
        roles.add(body.role)
        people.add(body.person_id)
        groups.add(body.custody_group)
        keys.add(body.key_id)
    if roles != {"CUSTOMER_ORIGIN_OWNER", "SECURITY_CUSTODIAN"}:
        raise EnrollmentRejected("missing required independent custody role")
    return FrozenScope(contract_sha256=contract.digest())
