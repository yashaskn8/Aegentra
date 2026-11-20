"""Bounded, deterministic audit-stream reconciliation for external witnessing.

The verifier checks every ordered event hash and predecessor link in a
window. Only a trusted independent source of complete immutable audit data
can turn this into evidence against database-administrator compromise.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Sequence
from uuid import UUID

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
        digest = hashlib.sha256(
            b"aegentra.audit.v1\x00"
            + org_id.bytes + stream.encode("ascii") + b"\x00"
            + seq.to_bytes(8, "big") + current + entry.body_hash
        ).digest()
        if digest != entry.event_hash:
            raise AuditGap("audit record hash is inconsistent with previous chain")
        current = digest
    if expected_head is not None and (
        len(expected_head) != 32 or current != expected_head
    ):
        raise AuditGap("reconciled sequence differs from advertised primary head")
    return VerifiedAuditHead(
        org_id=org_id, stream=stream, sequence=seq, sha256=current,
    )
