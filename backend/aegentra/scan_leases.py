"""Fenced PostgreSQL scan-attempt leases; no code execution or result trust.

SQS may deliver duplicate job IDs. PostgreSQL owns the generation, nonce,
attempt deadline, and acceptance of a *pending* untrusted result digest.
A trusted validator in a separate service must independently qualify results.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegentra.audit import record_event
from aegentra.db import ScanJob


@dataclass(frozen=True)
class Lease:
    job_id: UUID
    generation: int
    nonce: str
    expires_at: datetime
    attempt_deadline: datetime


async def acquire_lease(
    session: AsyncSession, *,
    org_id: UUID, job_id: UUID, actor_id: UUID, now: datetime,
) -> Lease | None:
    """Take a 90-second lease; never resurrect a retired generation."""
    if now.tzinfo is None:
        raise ValueError("lease timestamps must be timezone-aware")
    job = await session.scalar(
        select(ScanJob).where(ScanJob.org_id == org_id, ScanJob.id == job_id)
        .with_for_update()
    )
    if job is None or job.status not in {"QUEUED", "LEASED"}:
        return None
    if job.status == "LEASED" and job.lease_expires is not None and now < job.lease_expires:
        return None
    if job.attempts >= 3:
        job.status = "UNKNOWN"
        job.lease_nonce = None
        await record_event(
            session, org_id=org_id, actor_id=actor_id, stream="scan",
            event_type="SCAN_ATTEMPTS_EXHAUSTED", body={"job_id": str(job_id)},
        )
        return None

    job.attempts += 1
    job.attempt_generation += 1
    job.status = "LEASED"
    job.lease_nonce = secrets.token_urlsafe(32)
    job.attempt_deadline = now + timedelta(minutes=8)
    job.lease_expires = now + timedelta(seconds=90)
    job.result_sha256 = None
    await record_event(
        session, org_id=org_id, actor_id=actor_id, stream="scan",
        event_type="SCAN_LEASED",
        body={"job_id": str(job_id), "generation": job.attempt_generation},
    )
    return Lease(
        job_id=job_id, generation=job.attempt_generation,
        nonce=job.lease_nonce, expires_at=job.lease_expires,
        attempt_deadline=job.attempt_deadline,
    )


async def renew_lease(
    session: AsyncSession, *,
    org_id: UUID, job_id: UUID, generation: int, nonce: str, now: datetime,
) -> bool:
    job = await session.scalar(
        select(ScanJob).where(ScanJob.org_id == org_id, ScanJob.id == job_id)
        .with_for_update()
    )
    if not _active(job, generation=generation, nonce=nonce, now=now):
        return False
    job.lease_expires = min(job.attempt_deadline, now + timedelta(seconds=90))
    return True


async def submit_unverified_result(
    session: AsyncSession, *,
    org_id: UUID, job_id: UUID, actor_id: UUID,
    generation: int, nonce: str, result_sha256: bytes, now: datetime,
) -> bool:
    """Accept only the current attempt's digest, not a clean/safe verdict."""
    if len(result_sha256) != 32:
        raise ValueError("expected exactly 32 digest bytes")
    job = await session.scalar(
        select(ScanJob).where(ScanJob.org_id == org_id, ScanJob.id == job_id)
        .with_for_update()
    )
    if not _active(job, generation=generation, nonce=nonce, now=now):
        return False
    job.result_sha256 = result_sha256
    job.status = "PENDING_TRUSTED_VALIDATION"
    job.lease_nonce = None
    await record_event(
        session, org_id=org_id, actor_id=actor_id, stream="scan",
        event_type="SCAN_RESULT_RECEIVED_UNVERIFIED",
        body={"job_id": str(job_id), "generation": generation},
    )
    return True


def _active(job: ScanJob | None, *, generation: int, nonce: str, now: datetime) -> bool:
    return bool(
        job is not None
        and job.status == "LEASED"
        and job.attempt_generation == generation
        and job.lease_nonce == nonce
        and job.lease_expires is not None
        and job.attempt_deadline is not None
        and now < job.lease_expires
        and now < job.attempt_deadline
    )
