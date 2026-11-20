"""Bounded, deterministic audit-stream reconciliation for external witnessing.

The verifier checks every ordered event hash and predecessor link in a
window. Only a trusted independent source of complete immutable audit data
can turn this into evidence against database-administrator compromise.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Sequence
from uuid import UUID

from aegentra.audit import MAX_AUDIT_PAYLOAD, canonical_bytes
from aegentra.content_manifest import ManifestError, strict_json
from aegentra.db import AuditEntry


class AuditGap(ValueError):
    pass


MAX_AUDIT_WINDOW = 1000
_ZERO = b"\x00" * 32


@dataclass(frozen=True)
class VerifiedAuditHead:
    org_id: UUID
    stream: str
    sequence: int
    sha256: bytes


def reconcile_audit_window(
    *,
    org_id: UUID, stream: str,
    previous: VerifiedAuditHead | None,
    ordered: Sequence[AuditEntry],
    expected_head: bytes | None = None,
    expected_sequence: int | None = None,
) -> VerifiedAuditHead:
    """Verify one contiguous window, rejecting gaps, duplicates and forks."""
    if not stream or not stream.isascii() or len(stream) > 32:
        raise AuditGap("invalid audit stream identity")
    if not ordered or len(ordered) > MAX_AUDIT_WINDOW:
        raise AuditGap("empty or excessive audit window")
    if previous is not None and (
        previous.org_id != org_id or previous.stream != stream
        or previous.sequence <= 0 or len(previous.sha256) != 32
    ):
        raise AuditGap("prior audit checkpoint is wrong or untrusted")
    seq = 0 if previous is None else previous.sequence
    current = _ZERO if previous is None else previous.sha256
    for entry in ordered:
        seq += 1
        if (
            entry.org_id != org_id or entry.stream != stream
            or entry.sequence != seq
            or not isinstance(entry.previous_hash, bytes)
            or not isinstance(entry.event_hash, bytes)
            or not isinstance(entry.body_hash, bytes)
            or len(entry.previous_hash) != 32
            or len(entry.event_hash) != 32
            or len(entry.body_hash) != 32
            or entry.previous_hash != current
        ):
            raise AuditGap("audit sequence, tenant or predecessor diverges")
        raw = entry.payload_bytes
        if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_AUDIT_PAYLOAD:
            raise AuditGap("missing or unbounded canonical audit payload")
        if not isinstance(entry.created_at, datetime) or (
            entry.created_at.tzinfo is None or entry.created_at.utcoffset() is None
        ):
            raise AuditGap("audit timestamp lacks an accountable UTC identity")
        try:
            parsed = strict_json(raw, max_bytes=MAX_AUDIT_PAYLOAD)
            if (
                not isinstance(parsed, dict)
                or set(parsed) != {"kind", "actor_id", "event_type", "body", "created_at"}
                or parsed["kind"] != "aegentra.audit.payload.v2"
                or not isinstance(parsed["body"], dict)
                or parsed["actor_id"] != str(entry.actor_id)
                or parsed["event_type"] != entry.event_type
                or parsed["created_at"] != entry.created_at.astimezone(
                    timezone.utc
                ).isoformat(timespec="microseconds")
                or canonical_bytes(parsed) != raw
            ):
                raise AuditGap("audit event metadata differs from canonical payload")
        except (ManifestError, ValueError, TypeError, UnicodeError) as exc:
            raise AuditGap("audit event payload is invalid or has been altered") from exc
        if hashlib.sha256(raw).digest() != entry.body_hash:
            raise AuditGap("audit body digest does not match retained event bytes")
        digest = hashlib.sha256(
            b"aegentra.audit.v1\x00"
            + org_id.bytes + stream.encode("ascii") + b"\x00"
            + seq.to_bytes(8, "big") + current + entry.body_hash
        ).digest()
        if digest != entry.event_hash:
            raise AuditGap("audit record hash is inconsistent with previous chain")
        current = digest
    if expected_sequence is not None and (
        type(expected_sequence) is not int
        or expected_sequence <= 0 or seq != expected_sequence
    ):
        raise AuditGap("audit window does not reach expected terminal sequence")
    if expected_head is not None and (
        not isinstance(expected_head, bytes)
        or len(expected_head) != 32 or current != expected_head
    ):
        raise AuditGap("reconciled sequence differs from advertised primary head")
    return VerifiedAuditHead(
        org_id=org_id, stream=stream, sequence=seq, sha256=current,
    )
