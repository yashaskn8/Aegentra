"""Native at-least-once outbox claims with PostgreSQL fencing.

The dispatcher commits a lease BEFORE any network delivery. The sink must
deduplicate by immutable event ID and verify its own acknowledgment. No
exactly-once network guarantee is implied by a successful DB transaction.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import and_, exists, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from aegentra.db import AuditEntry, OutboxEvent

MAX_ATTEMPTS = 10
LEASE_SECONDS = 45
MAX_BATCH = 10
_ALLOWED_ERROR_CODES = frozenset({
    "TRANSIENT", "RATE_LIMIT", "DEPENDENCY_UNAVAILABLE", "UNKNOWN",
})
_RECEIPT = re.compile(r"^[A-Za-z0-9._:/=-]{8,128}$")


class DispatchRejected(ValueError):
    pass


@dataclass(frozen=True)
class OutboxClaim:
    org_id: UUID
    event_id: UUID
    stream: str
    sequence: int
    event_type: str
    audit_hash: str
    generation: int
    attempt: int
    nonce: str
    lease_expires: datetime


def _utc(now: datetime) -> None:
    if now.tzinfo is None or now.utcoffset() is None:
        raise DispatchRejected("trusted UTC dispatcher clock unavailable")


async def claim_outbox(
    session: AsyncSession, *,
    org_id: UUID, now: datetime, limit: int = MAX_BATCH,
) -> tuple[OutboxClaim, ...]:
    """One short transaction, SKIP LOCKED; never network-I/O while leased."""
    _utc(now)
    if not isinstance(org_id, UUID) or not 1 <= limit <= MAX_BATCH:
        raise DispatchRejected("invalid tenant or claim budget")
    earlier = aliased(OutboxEvent)
    predecessor_pending = exists(
        select(earlier.id).where(
            earlier.org_id == OutboxEvent.org_id,
            earlier.stream == OutboxEvent.stream,
            earlier.sequence < OutboxEvent.sequence,
            earlier.delivered_at.is_(None),
        )
    )
    rows = list((await session.scalars(
        select(OutboxEvent).where(
            OutboxEvent.org_id == org_id,
            OutboxEvent.delivered_at.is_(None),
            OutboxEvent.abandoned_at.is_(None),
            or_(OutboxEvent.lease_expires.is_(None), OutboxEvent.lease_expires <= now),
            or_(OutboxEvent.next_attempt_at.is_(None), OutboxEvent.next_attempt_at <= now),
            ~predecessor_pending,
        ).order_by(OutboxEvent.created_at, OutboxEvent.id)
        .limit(limit).with_for_update(skip_locked=True)
    )).all())
    claimed: list[OutboxClaim] = []
    for row in rows:
        if row.attempts >= MAX_ATTEMPTS:
            row.abandoned_at = now
            row.last_error_code = "ATTEMPTS_EXHAUSTED"
            row.lease_nonce_hash = None
            row.lease_expires = None
            continue
        audit = await session.scalar(
            select(AuditEntry.event_hash).where(
                AuditEntry.org_id == org_id,
                AuditEntry.stream == row.stream,
                AuditEntry.sequence == row.sequence,
            )
        )
        if audit is None or len(audit) != 32:
            raise DispatchRejected("outbox lacks matching immutable audit hash")
        nonce = secrets.token_urlsafe(32)
        row.attempts += 1
        row.lease_generation += 1
        row.lease_nonce_hash = hashlib.sha256(nonce.encode("ascii")).digest()
        row.lease_expires = now + timedelta(seconds=LEASE_SECONDS)
        row.next_attempt_at = None
        claimed.append(OutboxClaim(
            org_id=org_id, event_id=row.id, stream=row.stream,
            sequence=row.sequence, event_type=row.event_type,
            audit_hash=audit.hex(), generation=row.lease_generation,
            attempt=row.attempts, nonce=nonce,
            lease_expires=row.lease_expires,
        ))
    await session.flush()
    return tuple(claimed)


async def _locked_current(
    session: AsyncSession, *,
    org_id: UUID, event_id: UUID, generation: int, nonce: str,
) -> OutboxEvent | None:
    if not isinstance(org_id, UUID) or not isinstance(event_id, UUID):
        raise DispatchRejected("invalid dispatcher identity")
    if not isinstance(nonce, str) or len(nonce) != 43:
        raise DispatchRejected("invalid lease nonce")
    row = await session.scalar(
        select(OutboxEvent).where(
            OutboxEvent.org_id == org_id, OutboxEvent.id == event_id,
        ).with_for_update()
    )
    if (
        row is None or row.lease_generation != generation
        or row.lease_nonce_hash is None
        or not hmac.compare_digest(
            row.lease_nonce_hash, hashlib.sha256(nonce.encode("ascii")).digest()
        )
    ):
        return None
    return row


async def acknowledge_delivery(
    session: AsyncSession, *,
    org_id: UUID, event_id: UUID, generation: int, nonce: str,
    delivery_reference: str, now: datetime,
) -> bool:
    """Only after external sink confirms idempotent receipt of event ID."""
    _utc(now)
    if not _RECEIPT.fullmatch(delivery_reference):
        raise DispatchRejected("invalid external receipt reference")
    row = await _locked_current(
        session, org_id=org_id, event_id=event_id,
        generation=generation, nonce=nonce,
    )
    if row is None:
        return False
    if row.delivered_at is not None:
        return row.delivery_reference == delivery_reference
    if (
        row.abandoned_at is not None or row.lease_expires is None
        or now >= row.lease_expires
    ):
        return False
    row.delivered_at = now
    row.delivery_reference = delivery_reference
    row.lease_expires = None
    row.next_attempt_at = None
    row.last_error_code = None
    await session.flush()
    return True


async def fail_delivery(
    session: AsyncSession, *,
    org_id: UUID, event_id: UUID, generation: int, nonce: str,
    code: str, now: datetime,
) -> str:
    """Schedule bounded retry; preserve the event for operator intervention."""
    _utc(now)
    if code not in _ALLOWED_ERROR_CODES:
        raise DispatchRejected("untrusted external error code")
    row = await _locked_current(
        session, org_id=org_id, event_id=event_id,
        generation=generation, nonce=nonce,
    )
    if row is None or row.delivered_at is not None or row.abandoned_at is not None:
        return "STALE"
    if row.lease_expires is None or now >= row.lease_expires:
        return "STALE"
    row.lease_nonce_hash = None
    row.lease_expires = None
    row.last_error_code = code
    if row.attempts >= MAX_ATTEMPTS:
        row.abandoned_at = now
        row.next_attempt_at = None
        result = "EXHAUSTED"
    else:
        row.next_attempt_at = now + timedelta(seconds=min(2 ** row.attempts, 300))
        result = "RETRY_SCHEDULED"
    await session.flush()
    return result
