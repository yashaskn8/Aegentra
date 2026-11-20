"""Transactional, tenant-scoped staging tickets for independently verified uploads.

These tickets grant no approval or trust. Only a separate verifier may later
promote explicitly pinned S3 object versions to sealed evidence.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from aegentra.audit import IdempotencyConflict, canonical_bytes, record_event
from aegentra.content_manifest import ContentManifest
from aegentra.db import Asset, IdempotencyRequest, StagingPart, StagingUpload


class UploadUnavailable(Exception):
    pass


class UploadConflict(Exception):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


async def create_ticket(
    session: AsyncSession, *,
    org_id: UUID, actor_id: UUID, asset_id: UUID,
    idempotency_key: str, manifest: ContentManifest,
) -> dict:
    """One transaction: idempotency, declaration, audit and outbox."""
    content_digest = manifest.sha256()
    request_hash = hashlib.sha256(canonical_bytes({
        "asset_id": str(asset_id), "content_sha256": content_digest,
    })).digest()
    route = "POST /v1/assets/{asset_id}/uploads"

    await session.execute(
        pg_insert(IdempotencyRequest).values(
            org_id=org_id, identity_id=actor_id, route=route,
            key=idempotency_key, request_hash=request_hash,
            response={}, status=0, created_at=utc_now(),
        ).on_conflict_do_nothing(
            index_elements=["org_id", "identity_id", "route", "key"]
        )
    )
    request = await session.scalar(
        select(IdempotencyRequest).where(
            IdempotencyRequest.org_id == org_id,
            IdempotencyRequest.identity_id == actor_id,
            IdempotencyRequest.route == route,
            IdempotencyRequest.key == idempotency_key,
        ).with_for_update()
    )
    if request is None or request.request_hash != request_hash:
        raise IdempotencyConflict("idempotency key reused for different upload")
    if request.status == 201:
        # Reauthorize each retry at the API boundary; return current ticket state.
        ticket_id = UUID(request.response["id"])
        ticket = await session.scalar(
            select(StagingUpload).where(
                StagingUpload.org_id == org_id, StagingUpload.id == ticket_id
            )
        )
        if ticket is None or ticket.issued_by != actor_id:
            raise UploadUnavailable("upload ticket unavailable")
        return {**request.response, "status": (
            "EXPIRED" if ticket.status == "ISSUED" and utc_now() >= ticket.expires_at
            else ticket.status
        )}
    if request.status != 0:
        raise IdempotencyConflict("unknown idempotency state")

    asset = await session.scalar(
        select(Asset.id).where(Asset.org_id == org_id, Asset.id == asset_id)
    )
    if asset is None:
        raise UploadUnavailable("asset unavailable")

    now = utc_now()
    upload_id = uuid4()
    ticket = StagingUpload(
        org_id=org_id, id=upload_id, asset_id=asset_id, issued_by=actor_id,
        content_digest=bytes.fromhex(content_digest),
        content_manifest=json.loads(manifest.canonical_bytes()),
        status="ISSUED", created_at=now, expires_at=now + timedelta(minutes=15),
    )
    session.add(ticket)
    parts = []
    for index, part in enumerate(sorted(manifest.parts, key=lambda item: item.path)):
        key = f"staging/{org_id.hex}/{upload_id.hex}/part-{index:02d}"
        session.add(StagingPart(
            org_id=org_id, upload_id=upload_id, part_index=index,
            path=part.path, content_sha256=bytes.fromhex(part.sha256),
            byte_length=part.byte_length, media_type=part.media_type,
            object_key=key,
        ))
        parts.append({
            "path": part.path, "object_key": key,
            "byte_length": part.byte_length,
            "sha256": part.sha256, "media_type": part.media_type,
        })
    result = {
        "id": str(upload_id), "asset_id": str(asset_id),
        "content_sha256": content_digest, "status": "ISSUED",
        "expires_at": ticket.expires_at.isoformat(),
        "parts": parts,
    }
    await record_event(
        session, org_id=org_id, actor_id=actor_id, stream="intake",
        event_type="UPLOAD_DECLARED",
        body={"upload_id": str(upload_id), "content_sha256": content_digest},
    )
    request.response, request.status = result, 201
    return result


async def finalize_ticket(
    session: AsyncSession, *,
    org_id: UUID, actor_id: UUID, upload_id: UUID,
    content_sha256: str, versions: dict[str, str],
) -> dict:
    """Pin exact claimed S3 versions; NEVER assert they are verified."""
    ticket = await session.scalar(
        select(StagingUpload).where(
            StagingUpload.org_id == org_id,
            StagingUpload.id == upload_id,
            StagingUpload.issued_by == actor_id,
        ).with_for_update()
    )
    if ticket is None:
        raise UploadUnavailable("upload unavailable")
    if ticket.content_digest.hex() != content_sha256:
        raise UploadConflict("content digest differs from issued ticket")

    parts = list((await session.scalars(
        select(StagingPart).where(
            StagingPart.org_id == org_id, StagingPart.upload_id == upload_id
        ).order_by(StagingPart.part_index)
    )).all())
    expected = {part.path for part in parts}
    if set(versions) != expected:
        raise UploadConflict("every declared part needs exactly one version")
    if ticket.status == "AWAITING_VERIFICATION":
        if all(part.version_id == versions[part.path] for part in parts):
            return {"id": str(upload_id), "status": ticket.status}
        raise UploadConflict("a finalized version set cannot be changed")
    if ticket.status != "ISSUED" or utc_now() >= ticket.expires_at:
        raise UploadConflict("upload ticket is no longer active")

    for part in parts:
        part.version_id = versions[part.path]
    ticket.status = "AWAITING_VERIFICATION"
    await record_event(
        session, org_id=org_id, actor_id=actor_id, stream="intake",
        event_type="UPLOAD_FINALIZATION_REQUESTED",
        body={"upload_id": str(upload_id), "content_sha256": content_sha256},
    )
    return {"id": str(upload_id), "status": "AWAITING_VERIFICATION"}
