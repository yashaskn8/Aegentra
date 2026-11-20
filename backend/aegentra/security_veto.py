"""Independent security-account STOP, without any workload database dependency.

The security account owns a versioned current pointer and append-only stop
records. A failed conditional pointer update means containment is UNKNOWN,
not successful. There is intentionally no 'clear' or emergency-allow command.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from uuid import UUID

import rfc8785
from pydantic import BaseModel, ConfigDict, Field

from aegentra.content_manifest import ManifestError, strict_json
from aegentra.gateway_signatures import (
    SignedVeto, VetoSnapshot, _verify_pinned_key, veto_message,
)

MAX_ROOT_BYTES = 4096
_HEX = r"^[0-9a-f]{64}$"


class SecurityRootError(ValueError):
    pass


class StopUnknown(SecurityRootError):
    """STOP intent exists, but its active state has not been confirmed."""


class SecurityRootState(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["aegentra.security.root-state.v1"]
    org_id: UUID
    incarnation: UUID
    root_generation: int = Field(strict=True, gt=0)
    veto_generation: int = Field(strict=True, ge=0)
    state: Literal["CLEAR", "STOP"]
    predecessor_sha256: str = Field(pattern=_HEX)
    incident_id: UUID
    written_at: datetime


@dataclass(frozen=True)
class CurrentState:
    body: SecurityRootState
    version_id: str
    etag_for_cas: str
    sha256: str


@dataclass(frozen=True)
class StopResult:
    veto_generation: int
    status: Literal["VETO_RECORDED_PENDING_ACK"]
    record_version_id: str | None


class SecurityAccountVeto:
    """Separate security-account S3 client, no reusable cached root state."""

    def __init__(
        self, *, s3: Any, sts: Any, bucket: str,
        expected_account: str, org_id: UUID, pinned_incarnation: UUID,
        minimum_root_generation: int, minimum_veto_generation: int = 0,
    ):
        if (
            not bucket or len(expected_account) != 12
            or not expected_account.isdecimal()
            or minimum_root_generation < 1 or minimum_veto_generation < 0
        ):
            raise ValueError("security root enrollment incomplete")
        self.s3, self.sts, self.bucket = s3, sts, bucket
        self.expected_account = expected_account
        self.org_id, self.incarnation = org_id, pinned_incarnation
        self.minimum_root_generation = minimum_root_generation
        self.minimum_veto_generation = minimum_veto_generation

    def _check_account(self) -> None:
        if self.sts.get_caller_identity().get("Account") != self.expected_account:
            raise SecurityRootError("untrusted security-account identity")

    @property
    def current_key(self) -> str:
        return f"security-root/v1/{self.org_id.hex}/current"

    def current(self) -> CurrentState:
        """Read latest state fresh; S3 VersionId and ETag are not integrity hashes."""
        self._check_account()
        record = self.s3.get_object(Bucket=self.bucket, Key=self.current_key)
        version, etag = record.get("VersionId"), record.get("ETag")
        length = record.get("ContentLength")
        if (
            not isinstance(version, str) or version in ("", "null")
            or not isinstance(etag, str) or not etag
            or not isinstance(length, int) or not 0 < length <= MAX_ROOT_BYTES
        ):
            raise SecurityRootError("unversioned or unbounded security-root pointer")
        stream = record.get("Body")
        if stream is None:
            raise SecurityRootError("missing security-root body")
        try:
            raw = stream.read(MAX_ROOT_BYTES + 1)
        finally:
            stream.close()
        if not isinstance(raw, bytes) or len(raw) != length:
            raise SecurityRootError("security-root bytes are truncated")
        try:
            parsed = strict_json(raw, max_bytes=MAX_ROOT_BYTES)
            if not isinstance(parsed, dict) or rfc8785.dumps(parsed) != raw:
                raise SecurityRootError("noncanonical security-root state")
            state = SecurityRootState.model_validate(parsed)
        except (ManifestError, ValueError, TypeError) as exc:
            raise SecurityRootError("invalid security-root state") from exc
        if (
            state.org_id != self.org_id
            or state.incarnation != self.incarnation
            or state.root_generation < self.minimum_root_generation
            or state.veto_generation < self.minimum_veto_generation
            or state.written_at.tzinfo is None
        ):
            raise SecurityRootError("security-root state below enrolled generation")
        return CurrentState(
            body=state, version_id=version, etag_for_cas=etag,
            sha256=hashlib.sha256(raw).hexdigest(),
        )

    def emergency_stop(self, *, incident_id: UUID, now: datetime) -> StopResult:
        """Append immutable intent, then CAS root; never claim all gateways stopped."""
        if now.tzinfo is None or now.utcoffset() is None:
            raise SecurityRootError("trusted UTC incident clock unavailable")
        previous = self.current()
        if previous.body.state == "STOP":
            return StopResult(
                veto_generation=previous.body.veto_generation,
                status="VETO_RECORDED_PENDING_ACK", record_version_id=None,
            )
        state = SecurityRootState(
            kind="aegentra.security.root-state.v1",
            org_id=self.org_id, incarnation=self.incarnation,
            root_generation=previous.body.root_generation,
            veto_generation=previous.body.veto_generation + 1,
            state="STOP", predecessor_sha256=previous.sha256,
            incident_id=incident_id, written_at=now.astimezone(timezone.utc),
        )
        raw = rfc8785.dumps(state.model_dump(mode="json"))
        if len(raw) > MAX_ROOT_BYTES:
            raise SecurityRootError("security STOP record exceeds bound")
        checksum = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii")
        record_key = (
            f"security-root/v1/{self.org_id.hex}/stops/"
            f"{state.veto_generation:020d}/{incident_id.hex}"
        )
        try:
            appended = self.s3.put_object(
                Bucket=self.bucket, Key=record_key, Body=raw,
                ContentType="application/json", IfNoneMatch="*",
                ChecksumSHA256=checksum,
            )
            recorded_version = appended.get("VersionId")
            if not isinstance(recorded_version, str) or recorded_version in ("", "null"):
                raise StopUnknown("STOP record has no immutable S3 version")
            pointer = self.s3.put_object(
                Bucket=self.bucket, Key=self.current_key, Body=raw,
                ContentType="application/json", IfMatch=previous.etag_for_cas,
                ChecksumSHA256=checksum,
            )
            version = pointer.get("VersionId")
            if not isinstance(version, str) or version in ("", "null"):
                raise StopUnknown("STOP pointer update is not versioned")
        except Exception as exc:
            raise StopUnknown("STOP not confirmed; containment unknown") from exc
        return StopResult(
            veto_generation=state.veto_generation,
            status="VETO_RECORDED_PENDING_ACK",
            record_version_id=recorded_version,
        )

    def fresh_snapshot(self, *, nonce: str, now: datetime) -> VetoSnapshot:
        """Re-read current security root for every gateway challenge."""
        if now.tzinfo is None or now.utcoffset() is None:
            raise SecurityRootError("trusted gateway clock unavailable")
        record = self.current()
        timestamp = now.astimezone(timezone.utc)
        return VetoSnapshot(
            kind="aegentra.security.veto-state.v1",
            audience="aegentra-protected-gateway",
            request_nonce=nonce,
            org_id=self.org_id, incarnation=self.incarnation,
            root_generation=record.body.root_generation,
            veto_generation=record.body.veto_generation,
            state=record.body.state,
            issued_at=timestamp, expires_at=timestamp + timedelta(seconds=1),
        )


class KmsVetoSigner:
    """Use a pinned P-256 public key to check AWS KMS signatures locally."""

    def __init__(self, *, kms: Any, key_id: str, pinned_public_der: bytes):
        if not key_id:
            raise ValueError("configured security KMS key ID required")
        self.kms, self.key_id, self.pinned_public_der = (
            kms, key_id, pinned_public_der,
        )

    def sign(self, body: VetoSnapshot) -> SignedVeto:
        message = veto_message(body)
        if len(message) > 4096:
            raise SecurityRootError("signed veto snapshot exceeds KMS raw bound")
        result = self.kms.sign(
            KeyId=self.key_id, Message=message,
            MessageType="RAW", SigningAlgorithm="ECDSA_SHA_256",
        )
        signature = result.get("Signature")
        if not isinstance(signature, bytes):
            raise SecurityRootError("missing KMS veto signature")
        _verify_pinned_key(self.pinned_public_der, signature, message)
        return SignedVeto(body, signature)
