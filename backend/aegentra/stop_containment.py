"""Conservative cross-domain STOP acknowledgment and response-drain oracle.

A security-account veto is not proof all gateways stopped. The enrolled
authority and every independently known gateway must sign their own receipt,
then the maximum already-admitted write window must drain. No remote CLEAR.
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

from aegentra.security_veto import SecurityRootState


class ContainmentRejected(ValueError):
    pass


class AuthorityFence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["aegentra.incident.authority-fenced.v1"]
    audience: Literal["aegentra-stop-containment"]
    org_id: UUID
    incarnation: UUID
    target_id: UUID
    veto_generation: int = Field(strict=True, gt=0)
    target_epoch: int = Field(strict=True, gt=0)
    guard: Literal["STOP_SERVING"]
    signer_key_id: str = Field(min_length=3, max_length=128)
    fenced_at: datetime
    signed_at: datetime

    @model_validator(mode="after")
    def valid_times(self) -> "AuthorityFence":
        if (
            self.fenced_at.tzinfo is None
            or self.signed_at.tzinfo is None
            or not self.fenced_at <= self.signed_at
            or self.signed_at - self.fenced_at > timedelta(seconds=30)
        ):
            raise ValueError("authority fence clock invalid")
        return self

    def canonical(self) -> bytes:
        return rfc8785.dumps(self.model_dump(mode="json"))


class GatewayStopAck(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["aegentra.incident.gateway-stopped.v1"]
    audience: Literal["aegentra-stop-containment"]
    org_id: UUID
    incarnation: UUID
    target_id: UUID
    gateway_id: str = Field(min_length=3, max_length=128)
    veto_generation: int = Field(strict=True, gt=0)
    state: Literal["STOP"]
    signer_key_id: str = Field(min_length=3, max_length=128)
    admissions_closed_at: datetime
    last_write_deadline: datetime
    signed_at: datetime

    @model_validator(mode="after")
    def valid_times(self) -> "GatewayStopAck":
        if (
            self.admissions_closed_at.tzinfo is None
            or self.last_write_deadline.tzinfo is None
            or self.signed_at.tzinfo is None
            or not self.admissions_closed_at <= self.signed_at
            or not self.admissions_closed_at <= self.last_write_deadline
            or self.last_write_deadline - self.admissions_closed_at > timedelta(seconds=30)
        ):
            raise ValueError("gateway admitted-response cutoff invalid")
        return self

    def canonical(self) -> bytes:
        return rfc8785.dumps(self.model_dump(mode="json"))


@dataclass(frozen=True)
class SignerCredential:
    key_id: str
    public_der: bytes
    independently_enrolled: bool
    active: bool = True


@dataclass(frozen=True)
class SignedFence:
    body: AuthorityFence
    signature_der: bytes


@dataclass(frozen=True)
class SignedGatewayAck:
    body: GatewayStopAck
    signature_der: bytes


@dataclass(frozen=True)
class ContainmentAssessment:
    phase: str
    contained: bool
    missing_gateways: tuple[str, ...]


def fence_message(body: AuthorityFence) -> bytes:
    return b"aegentra.incident.authority-fence.signature.v1\x00" + body.canonical()


def gateway_ack_message(body: GatewayStopAck) -> bytes:
    return b"aegentra.incident.gateway-stop.signature.v1\x00" + body.canonical()


def _validate_signature(
    *, key: SignerCredential, signer_key_id: str,
    signature: bytes, message: bytes,
) -> None:
    if (
        not key.independently_enrolled or not key.active
        or key.key_id != signer_key_id
        or not 8 <= len(signature) <= 128
    ):
        raise ContainmentRejected("unqualified or revoked containment signer")
    try:
        public = serialization.load_der_public_key(key.public_der)
        if (
            not isinstance(public, ec.EllipticCurvePublicKey)
            or not isinstance(public.curve, ec.SECP256R1)
        ):
            raise ContainmentRejected("invalid containment key algorithm")
        public.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ContainmentRejected("invalid independent containment signature") from exc


def assess_stop_containment(
    *, root: SecurityRootState, target_id: UUID,
    authority_fence: SignedFence | None,
    authority_key: SignerCredential,
    gateway_acks: tuple[SignedGatewayAck, ...],
    enrolled_gateways: dict[str, SignerCredential],
    now: datetime, drain_margin: timedelta = timedelta(seconds=2),
) -> ContainmentAssessment:
    """Take only trusted, freshly acquired security-root and enrollment inputs.

    No caller-provided list of gateways may be used as enrollment authority.
    Missing/forged receipts can never result in a contained decision.
    """
    if now.tzinfo is None or now.utcoffset() is None:
        raise ContainmentRejected("trusted UTC clock unavailable")
    if not timedelta(0) <= drain_margin <= timedelta(seconds=10):
        raise ContainmentRejected("unbounded response drain margin")
    moment = now.astimezone(timezone.utc)
    if (
        root.written_at.tzinfo is None
        or root.written_at > moment + timedelta(seconds=30)
        or root.state != "STOP" or root.veto_generation <= 0
    ):
        return ContainmentAssessment("VETO_NOT_CONFIRMED", False, ())
    if authority_fence is None:
        return ContainmentAssessment("VETO_RECORDED", False, tuple(sorted(enrolled_gateways)))

    fence = authority_fence.body
    _validate_signature(
        key=authority_key, signer_key_id=fence.signer_key_id,
        signature=authority_fence.signature_der,
        message=fence_message(fence),
    )
    if (
        fence.org_id != root.org_id
        or fence.incarnation != root.incarnation
        or fence.target_id != target_id
        or fence.veto_generation < root.veto_generation
        or fence.fenced_at < root.written_at
        or fence.signed_at > moment + timedelta(seconds=30)
    ):
        raise ContainmentRejected("fence not bound to current security STOP")

    if not enrolled_gateways:
        return ContainmentAssessment("AUTHORITY_FENCED", False, ())
    observed: dict[str, GatewayStopAck] = {}
    for envelope in gateway_acks:
        ack = envelope.body
        if ack.gateway_id in observed:
            raise ContainmentRejected("duplicate gateway stop acknowledgment")
        credential = enrolled_gateways.get(ack.gateway_id)
        if credential is None:
            raise ContainmentRejected("unrecognized gateway identity")
        _validate_signature(
            key=credential, signer_key_id=ack.signer_key_id,
            signature=envelope.signature_der,
            message=gateway_ack_message(ack),
        )
        if (
            ack.org_id != root.org_id
            or ack.incarnation != root.incarnation
            or ack.target_id != target_id
            or ack.veto_generation < root.veto_generation
            or ack.admissions_closed_at < root.written_at
            or ack.signed_at > moment + timedelta(seconds=30)
        ):
            raise ContainmentRejected("gateway stop acknowledgment stale or out of scope")
        observed[ack.gateway_id] = ack

    missing = tuple(sorted(set(enrolled_gateways) - set(observed)))
    if missing:
        return ContainmentAssessment("AUTHORITY_FENCED", False, missing)
    latest_write = max(item.last_write_deadline for item in observed.values())
    if moment < latest_write + drain_margin:
        return ContainmentAssessment("GATEWAYS_ACKNOWLEDGED_DRAINING", False, ())
    return ContainmentAssessment("CONTAINED", True, ())
