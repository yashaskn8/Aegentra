"""Transactional audit, outbox and idempotent asset registration.

The database hash chain is independently checkable but NOT tamper-proof against
a privileged database administrator. External witnessing belongs to SA-1.1 S3.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from aegentra.asset_store import create_asset
from aegentra.db import AuditEntry, AuditStream, IdempotencyRequest, OutboxEvent


MAX_AUDIT_PAYLOAD = 64 * 1024


class IdempotencyConflict(Exception):
    pass


def canonical_bytes(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


async def record_event(
    session: AsyncSession,
    *,
    org_id: UUID,
    actor_id: UUID,
    event_type: str,
    body: dict,
    stream: str = "assets",
) -> AuditEntry:
    await session.execute(
        pg_insert(AuditStream)
        .values(org_id=org_id, stream=stream, sequence=0, head_hash=b"\x00" * 32)
        .on_conflict_do_nothing(index_elements=["org_id", "stream"])
    )
    head = await session.scalar(
        select(AuditStream)
        .where(AuditStream.org_id == org_id, AuditStream.stream == stream)
        .with_for_update()
    )
    if head is None:
        raise RuntimeError("audit stream unavailable")
    seq = head.sequence + 1
    created_at = datetime.now(timezone.utc)
    payload = canonical_bytes({
        "kind": "aegentra.audit.payload.v2",
        "event_type": event_type, "actor_id": str(actor_id), "body": body,
        "created_at": created_at.isoformat(timespec="microseconds"),
    })
    if not 0 < len(payload) <= MAX_AUDIT_PAYLOAD:
        raise ValueError("audit payload exceeds the retained-byte bound")
    body_hash = hashlib.sha256(payload).digest()
    event_hash = hashlib.sha256(
        b"aegentra.audit.v1\x00"
        + org_id.bytes + stream.encode("ascii") + b"\x00"
        + seq.to_bytes(8, "big") + head.head_hash + body_hash
    ).digest()
    entry = AuditEntry(
        org_id=org_id, stream=stream, sequence=seq, actor_id=actor_id,
        event_type=event_type, previous_hash=head.head_hash,
        event_hash=event_hash, body_hash=body_hash,
        payload_bytes=payload, created_at=created_at,
    )
    session.add(entry)
    head.sequence = seq
    head.head_hash = event_hash
    await session.flush()
    session.add(
        OutboxEvent(
            id=uuid4(), org_id=org_id, stream=stream, sequence=seq,
            event_type=event_type, created_at=datetime.now(timezone.utc),
        )
    )
    return entry


async def register_asset(
    session: AsyncSession,
    *,
    org_id: UUID,
    actor_id: UUID,
    key: str,
    slug: str,
    criticality: str,
) -> dict:
    """One DB transaction creates exactly one asset, audit entry and outbox event."""
    route = "POST /v1/assets"
    request_hash = hashlib.sha256(
        canonical_bytes({"slug": slug, "criticality": criticality})
    ).digest()
    await session.execute(
        pg_insert(IdempotencyRequest)
        .values(
            org_id=org_id, identity_id=actor_id, route=route, key=key,
            request_hash=request_hash, response={}, status=0,
            created_at=datetime.now(timezone.utc),
        )
        .on_conflict_do_nothing(index_elements=["org_id", "identity_id", "route", "key"])
    )
    request = await session.scalar(
        select(IdempotencyRequest)
        .where(
            IdempotencyRequest.org_id == org_id,
            IdempotencyRequest.identity_id == actor_id,
            IdempotencyRequest.route == route,
            IdempotencyRequest.key == key,
        )
        .with_for_update()
    )
    if request is None or request.request_hash != request_hash:
        raise IdempotencyConflict("idempotency key reused with a different request")
    if request.status == 201:
        return dict(request.response)
    if request.status != 0:
        raise IdempotencyConflict("idempotency request in an unknown state")

    asset = await create_asset(
        session, org_id=org_id, slug=slug, criticality=criticality,
    )
    result = {"id": str(asset.id), "slug": asset.slug, "criticality": asset.criticality}
    await record_event(
        session, org_id=org_id, actor_id=actor_id,
        event_type="ASSET_REGISTERED",
        body={"asset_id": str(asset.id), "criticality": asset.criticality},
    )
    request.response = result
    request.status = 201
    return result
