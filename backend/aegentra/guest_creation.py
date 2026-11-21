"""Durable, fenced native EC2/EBS creation intents.

Every AWS create must have a committed PREPARED intent first. UNKNOWN is
terminal until an independently audited reconciliation; it is NEVER safe to
blindly retry a non-idempotent or ambiguous physical operation. No AWS SDK
calls take place here; the caller must commit before and after any AWS IO.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegentra.audit import record_event
from aegentra.db import GuestAttempt, GuestCreateIntent, GuestResource, ScanJob


class CreationConflict(ValueError):
    pass


KINDS = ("INPUT_EBS", "OUTPUT_EBS", "INSTANCE")
_RESOURCE_ID = {
    "INPUT_EBS": re.compile(r"vol-[0-9a-f]{8,17}\Z"),
    "OUTPUT_EBS": re.compile(r"vol-[0-9a-f]{8,17}\Z"),
    "INSTANCE": re.compile(r"i-[0-9a-f]{8,17}\Z"),
}


def _time(now: datetime) -> None:
    if now.tzinfo is None or now.utcoffset() is None:
        raise CreationConflict("creation journal requires a trusted aware clock")


def _hex(value: str) -> bytes:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise CreationConflict("creation digest or token must be exact SHA-256 hex")
    return bytes.fromhex(value)


async def _locked(
    session: AsyncSession, org_id: UUID, job_id: UUID, generation: int,
) -> tuple[ScanJob, GuestAttempt]:
    # Match the global job -> attempt lock order.
    job = await session.scalar(select(ScanJob).where(
        ScanJob.org_id == org_id, ScanJob.id == job_id,
    ).with_for_update())
    attempt = await session.scalar(select(GuestAttempt).where(
        GuestAttempt.org_id == org_id, GuestAttempt.job_id == job_id,
        GuestAttempt.generation == generation,
    ).with_for_update())
    if job is None or attempt is None or job.attempt_generation != generation:
        raise CreationConflict("unavailable or fenced physical scan attempt")
    return job, attempt


def _live(job: ScanJob, attempt: GuestAttempt, now: datetime) -> bool:
    if (
        job.status != "LEASED" or job.lease_nonce is None
        or job.lease_expires is None or job.attempt_deadline is None
        or attempt.state in {"QUARANTINED", "DISPOSED"}
    ):
        return False
    return (
        now + timedelta(seconds=15) < job.lease_expires
        and now + timedelta(seconds=15) < job.attempt_deadline
        and hmac.compare_digest(
            attempt.nonce_sha256,
            hashlib.sha256(job.lease_nonce.encode("ascii")).digest(),
        )
    )


async def prepare_creation(
    session: AsyncSession, *, org_id: UUID, job_id: UUID,
    generation: int, actor_id: UUID, kind: str,
    plan_sha256: str, client_token: str, now: datetime,
) -> None:
    """Commit before the first AWS create call; never prepare a second time."""
    _time(now)
    digest = _hex(plan_sha256)
    _hex(client_token)
    if kind not in KINDS:
        raise CreationConflict("unexpected physical creation kind")
    job, attempt = await _locked(session, org_id, job_id, generation)
    if not _live(job, attempt, now):
        raise CreationConflict("physical creation lease is expired or unqualified")
    intents = list((await session.scalars(select(GuestCreateIntent).where(
        GuestCreateIntent.org_id == org_id, GuestCreateIntent.job_id == job_id,
        GuestCreateIntent.generation == generation,
    ))).all())
    if any(item.status != "RECORDED" or item.plan_sha256 != digest for item in intents):
        raise CreationConflict("prior physical create is unresolved or mismatched")
    completed = {item.kind for item in intents}
    prior_required = {
        "INPUT_EBS": set(),
        "OUTPUT_EBS": {"INPUT_EBS"},
        "INSTANCE": {"INPUT_EBS", "OUTPUT_EBS"},
    }[kind]
    states = {
        "INPUT_EBS": "RESERVED",
        "OUTPUT_EBS": "RESERVED",
        "INSTANCE": "VOLUMES_RECORDED",
    }
    if completed != prior_required or attempt.state != states[kind]:
        raise CreationConflict("physical creation is out of order or duplicated")
    resources = (await session.scalars(select(GuestResource.kind).where(
        GuestResource.org_id == org_id, GuestResource.job_id == job_id,
        GuestResource.generation == generation,
    ))).all()
    if set(resources) != prior_required or len(resources) != len(prior_required):
        raise CreationConflict("physical inventory does not match completed intents")
    if now < attempt.updated_at:
        raise CreationConflict("creation clock predates custody state")
    session.add(GuestCreateIntent(
        org_id=org_id, job_id=job_id, generation=generation, kind=kind,
        plan_sha256=digest,
        token_sha256=hashlib.sha256(client_token.encode("ascii")).digest(),
        status="PREPARED", created_at=now, updated_at=now,
    ))
    await session.flush()
    await record_event(
        session, org_id=org_id, actor_id=actor_id, stream="scan",
        event_type="GUEST_CREATE_PREPARED",
        body={"job_id": str(job_id), "generation": generation, "kind": kind},
    )


async def record_creation(
    session: AsyncSession, *, org_id: UUID, job_id: UUID,
    generation: int, actor_id: UUID, kind: str,
    client_token: str, plan_sha256: str, resource_id: str, now: datetime,
) -> str:
    """Durably record a known physical ID, including if the lease went stale.

    A stale success is tracked for janitor work but the attempt is quarantined.
    """
    _time(now)
    digest = _hex(plan_sha256)
    _hex(client_token)
    if kind not in KINDS or _RESOURCE_ID[kind].fullmatch(resource_id) is None:
        raise CreationConflict("untrusted physical resource identity")
    job, attempt = await _locked(session, org_id, job_id, generation)
    intent = await session.scalar(select(GuestCreateIntent).where(
        GuestCreateIntent.org_id == org_id, GuestCreateIntent.job_id == job_id,
        GuestCreateIntent.generation == generation, GuestCreateIntent.kind == kind,
    ).with_for_update())
    if (
        intent is None or intent.status != "PREPARED"
        or intent.plan_sha256 != digest
        or not hmac.compare_digest(
            intent.token_sha256,
            hashlib.sha256(client_token.encode("ascii")).digest(),
        )
        or now < intent.updated_at or now < attempt.updated_at
    ):
        raise CreationConflict("missing, stale or rewritten AWS create intent")
    if attempt.state != ("VOLUMES_RECORDED" if kind == "INSTANCE" else "RESERVED"):
        raise CreationConflict("physical create result arrived in wrong custody state")
    session.add(GuestResource(
        org_id=org_id, job_id=job_id, generation=generation,
        resource_id=resource_id, kind=kind,
    ))
    await session.flush()  # Unique global resource IDs block cross-attempt reuse.
    intent.status, intent.resource_id, intent.updated_at = "RECORDED", resource_id, now
    live = _live(job, attempt, now)
    if live:
        if kind == "OUTPUT_EBS":
            attempt.state = "VOLUMES_RECORDED"
        elif kind == "INSTANCE":
            attempt.state = "INSTANCE_RECORDED"
    else:
        attempt.state = "QUARANTINED"
    attempt.updated_at = now
    await record_event(
        session, org_id=org_id, actor_id=actor_id, stream="scan",
        event_type="GUEST_CREATE_RECORDED" if live else "GUEST_CREATE_STALE_QUARANTINED",
        body={"job_id": str(job_id), "generation": generation, "kind": kind},
    )
    return "RECORDED" if live else "RECORDED_QUARANTINED"


async def quarantine_creation(
    session: AsyncSession, *, org_id: UUID, job_id: UUID,
    generation: int, actor_id: UUID, kind: str, now: datetime,
) -> None:
    """Ambiguous AWS call: persist UNKNOWN and quarantine, never retry."""
    _time(now)
    if kind not in KINDS:
        raise CreationConflict("invalid AWS create operation kind")
    _, attempt = await _locked(session, org_id, job_id, generation)
    intent = await session.scalar(select(GuestCreateIntent).where(
        GuestCreateIntent.org_id == org_id, GuestCreateIntent.job_id == job_id,
        GuestCreateIntent.generation == generation, GuestCreateIntent.kind == kind,
    ).with_for_update())
    if intent is None or intent.status != "PREPARED":
        raise CreationConflict("AWS create intent is absent or already resolved")
    if now < intent.updated_at or now < attempt.updated_at:
        raise CreationConflict("creation quarantine clock moved backwards")
    intent.status, intent.updated_at = "UNKNOWN", now
    attempt.state, attempt.updated_at = "QUARANTINED", now
    await record_event(
        session, org_id=org_id, actor_id=actor_id, stream="scan",
        event_type="GUEST_CREATE_UNKNOWN_QUARANTINED",
        body={"job_id": str(job_id), "generation": generation, "kind": kind},
    )
