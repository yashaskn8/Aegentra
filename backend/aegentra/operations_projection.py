"""Authorized, read-only scan queue projection for the shadow console.

No raw evidence, lease nonce, guest address, or deployment decision is exposed.
Scan statuses are not statements that a scan was completed or qualified.
"""
from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegentra.db import ScanJob, StagingUpload


async def list_scan_status(session: AsyncSession, *, org_id: UUID) -> dict:
    rows = list((await session.execute(
        select(ScanJob, StagingUpload.asset_id)
        .join(
            StagingUpload,
            (StagingUpload.org_id == ScanJob.org_id)
            & (StagingUpload.id == ScanJob.upload_id),
        )
        .where(ScanJob.org_id == org_id)
        .order_by(ScanJob.created_at.desc(), ScanJob.id.desc())
        .limit(101)
    )).all())
    return {
        "items": [
            {
                "id": str(job.id),
                "asset_id": str(asset_id),
                "status": job.status,
                "attempts": job.attempts,
                "created_at": job.created_at.isoformat(),
            }
            for job, asset_id in rows[:100]
        ],
        "truncated": len(rows) > 100,
    }
