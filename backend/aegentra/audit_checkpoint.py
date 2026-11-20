"""Security-account witness for an existing transactional audit-stream hash.

The witness must independently reconcile the entire sequence/chain before
signing; a local database head is only a claim. KMS keys never enter the API.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import BaseModel, ConfigDict, Field

from aegentra.audit_reconcile import VerifiedAuditHead


class AuditCheckpointRejected(ValueError):
    pass


class AuditCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["aegentra.security.audit-checkpoint.v1"]
    audience: Literal["aegentra-immutable-audit-archive"]
    org_id: UUID
    incarnation: UUID
    stream: str = Field(min_length=1, max_length=32, pattern=r"^[a-z][a-z0-9_-]*$")
    sequence: int = Field(strict=True, gt=0)
    head_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    predecessor_checkpoint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    root_generation: int = Field(strict=True, gt=0)
    signer_key_id: str = Field(min_length=3, max_length=128)
    issued_at: datetime

    def canonical(self) -> bytes:
        return rfc8785.dumps(self.model_dump(mode="json"))


def checkpoint_message(body: AuditCheckpoint) -> bytes:
    return b"aegentra.security.audit-checkpoint.signature.v1\x00" + body.canonical()


def signed_checkpoint_bytes(body: AuditCheckpoint, signature_der: bytes) -> bytes:
    if not isinstance(signature_der, bytes) or not 8 <= len(signature_der) <= 128:
        raise AuditCheckpointRejected("invalid audit signature length")
    return rfc8785.dumps({
        "body": body.model_dump(mode="json"),
        "signature_der_hex": signature_der.hex(),
    })


def verify_checkpoint(
    *, body: AuditCheckpoint, signature_der: bytes,
    public_der: bytes, expected_key_id: str,
    org_id: UUID, incarnation: UUID, stream: str,
    minimum_sequence: int, expected_predecessor_sha256: str,
    minimum_root_generation: int, now: datetime,
) -> str:
    if now.tzinfo is None or now.utcoffset() is None:
        raise AuditCheckpointRejected("trusted independent clock required")
    if (
        body.org_id != org_id or body.incarnation != incarnation
        or body.stream != stream or body.sequence <= minimum_sequence
        or body.predecessor_checkpoint_sha256 != expected_predecessor_sha256
        or body.root_generation < minimum_root_generation
        or body.signer_key_id != expected_key_id
        or body.issued_at.tzinfo is None
        or body.issued_at.astimezone(timezone.utc) > now.astimezone(timezone.utc)
    ):
        raise AuditCheckpointRejected("audit checkpoint is stale or diverges")
    try:
        public = serialization.load_der_public_key(public_der)
        if (
            not isinstance(public, ec.EllipticCurvePublicKey)
            or not isinstance(public.curve, ec.SECP256R1)
        ):
            raise AuditCheckpointRejected("audit checkpoint must use P-256")
        public.verify(
            signature_der, checkpoint_message(body),
            ec.ECDSA(hashes.SHA256()),
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise AuditCheckpointRejected("independent checkpoint signature failed") from exc
    return hashlib.sha256(signed_checkpoint_bytes(body, signature_der)).hexdigest()


def require_reconciled_checkpoint_head(
    *, body: AuditCheckpoint, reconciled: "VerifiedAuditHead",
) -> None:
    """Bind a proposed checkpoint to independently reconciled audit bytes.

    This is only a consistency check; the caller must establish the provenance
    and completeness of the independent audit source before signing.
    """
    if (
        body.org_id != reconciled.org_id
        or body.stream != reconciled.stream
        or body.sequence != reconciled.sequence
        or not isinstance(reconciled.sha256, bytes)
        or len(reconciled.sha256) != 32
        or not hmac.compare_digest(body.head_sha256, reconciled.sha256.hex())
    ):
        raise AuditCheckpointRejected("checkpoint does not match reconciled audit head")


def verify_archived_checkpoint(
    *, raw: bytes, body: AuditCheckpoint, public_der: bytes,
    expected_key_id: str, minimum_sequence: int,
    expected_predecessor_sha256: str, minimum_root_generation: int,
    now: datetime,
) -> str:
    """Verify canonical archive bytes and the independently pinned signature."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 16 * 1024:
        raise AuditCheckpointRejected("invalid archived checkpoint size")
    try:
        envelope = json.loads(raw)
        if not isinstance(envelope, dict) or set(envelope) != {
            "body", "signature_der_hex",
        }:
            raise ValueError("invalid signed envelope")
        signature_hex = envelope["signature_der_hex"]
        if not isinstance(signature_hex, str) or len(signature_hex) > 256:
            raise ValueError("invalid signature encoding")
        signature = bytes.fromhex(signature_hex)
        if signed_checkpoint_bytes(body, signature) != raw:
            raise ValueError("archive body or canonical encoding differs")
    except (ValueError, TypeError, UnicodeDecodeError) as exc:
        raise AuditCheckpointRejected("archived checkpoint envelope rejected") from exc
    return verify_checkpoint(
        body=body, signature_der=signature, public_der=public_der,
        expected_key_id=expected_key_id, org_id=body.org_id,
        incarnation=body.incarnation, stream=body.stream,
        minimum_sequence=minimum_sequence,
        expected_predecessor_sha256=expected_predecessor_sha256,
        minimum_root_generation=minimum_root_generation, now=now,
    )


@dataclass(frozen=True)
class CheckpointRef:
    bucket: str
    key: str
    version_id: str
    sha256: str


@dataclass(frozen=True)
class CheckpointArchive:
    s3: Any
    sts: Any
    bucket: str
    security_account_id: str

    def _check_account(self) -> None:
        if (
            len(self.security_account_id) != 12
            or not self.security_account_id.isdecimal()
            or self.sts.get_caller_identity().get("Account") != self.security_account_id
        ):
            raise AuditCheckpointRejected("independent security-account identity missing")

    @staticmethod
    def key(body: AuditCheckpoint) -> str:
        return (
            f"audit-checkpoints/v1/{body.org_id.hex}/"
            f"{body.incarnation.hex}/{body.stream}/{body.sequence:020d}"
        )

    def append(self, body: AuditCheckpoint, signature_der: bytes) -> CheckpointRef:
        self._check_account()
        raw = signed_checkpoint_bytes(body, signature_der)
        if len(raw) > 16 * 1024:
            raise AuditCheckpointRejected("checkpoint record exceeds bound")
        digest = hashlib.sha256(raw).digest()
        key = self.key(body)
        response = self.s3.put_object(
            Bucket=self.bucket, Key=key, Body=raw,
            ContentType="application/json",
            IfNoneMatch="*", ChecksumSHA256=base64.b64encode(digest).decode("ascii"),
        )
        version = response.get("VersionId")
        if not isinstance(version, str) or version in ("", "null"):
            raise AuditCheckpointRejected("archive write lacks immutable version")
        return CheckpointRef(self.bucket, key, version, digest.hex())

    def read_exact(self, ref: CheckpointRef, *, body: AuditCheckpoint) -> bytes:
        self._check_account()
        if (
            ref.bucket != self.bucket or ref.key != self.key(body)
            or not ref.version_id or ref.version_id == "null"
            or len(ref.sha256) != 64
        ):
            raise AuditCheckpointRejected("wrong immutable checkpoint reference")
        response = self.s3.get_object(
            Bucket=self.bucket, Key=ref.key, VersionId=ref.version_id,
        )
        length = response.get("ContentLength")
        if (
            response.get("VersionId") != ref.version_id
            or not isinstance(length, int)
            or not 0 < length <= 16 * 1024
        ):
            raise AuditCheckpointRejected("checkpoint archive version unavailable")
        stream = response.get("Body")
        if stream is None:
            raise AuditCheckpointRejected("missing checkpoint bytes")
        try:
            raw = stream.read(16 * 1024 + 1)
        finally:
            stream.close()
        if (
            not isinstance(raw, bytes) or len(raw) != length
            or not hmac.compare_digest(
                hashlib.sha256(raw).hexdigest(), ref.sha256,
            )
        ):
            raise AuditCheckpointRejected("checkpoint archive bytes changed")
        return raw
