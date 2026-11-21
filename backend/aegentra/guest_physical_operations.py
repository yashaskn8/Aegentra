"""Bridge-only, journal-first native EBS attachment and termination intents.

No AWS calls here. A caller commits PREPARED, invokes exactly one AWS
operation outside the transaction, verifies fresh inventory where applicable,
then commits a terminal outcome. Any ambiguity blocks subsequent guest use.
"""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegentra.audit import record_event
from aegentra.bridge_custody import AttemptCustody
from aegentra.bridge_journal import _expected_custody
from aegentra.db import (
    GuestAttempt, GuestCreateIntent, GuestPhysicalOperation, ScanJob,
)
from aegentra.guest_creation import _live, _locked


class PhysicalConflict(ValueError):
    pass


ATTACH_DEVICES = {"ATTACH_INPUT": "/dev/sdf", "ATTACH_OUTPUT": "/dev/sdg"}
OPERATIONS = frozenset((*ATTACH_DEVICES, "TERMINATE"))


def _clock(now: datetime) -> None:
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise PhysicalConflict("trusted physical-operation clock unavailable")


async def _source(
    session: AsyncSession, *, org_id: UUID, job_id: UUID, generation: int,
    now: datetime,
) -> tuple[ScanJob, GuestAttempt, AttemptCustody, dict[str, GuestPhysicalOperation]]:
    _clock(now)
    job, attempt = await _locked(session, org_id, job_id, generation)
    if now < attempt.updated_at or attempt.state not in {"INSTANCE_RECORDED", "QUARANTINED"}:
        raise PhysicalConflict("unavailable or ineligible physical guest")
    expected = await _expected_custody(session, attempt)
    created = (await session.scalars(select(GuestCreateIntent).where(
        GuestCreateIntent.org_id == org_id, GuestCreateIntent.job_id == job_id,
        GuestCreateIntent.generation == generation,
    ))).all()
    resources = {
        "INPUT_EBS": expected.input_volume_id,
        "OUTPUT_EBS": expected.output_volume_id,
        "INSTANCE": expected.instance_id,
    }
    if (
        len(created) != 3
        or any(
            item.kind not in resources
            or item.resource_id != resources[item.kind]
            or item.status != "RECORDED"
            for item in created
        )
    ):
        raise PhysicalConflict("unverified physical creation journal")
    operations = (await session.scalars(select(GuestPhysicalOperation).where(
        GuestPhysicalOperation.org_id == org_id,
        GuestPhysicalOperation.job_id == job_id,
        GuestPhysicalOperation.generation == generation,
    ))).all()
    return job, attempt, expected, {item.kind: item for item in operations}


async def load_operation_state(
    session: AsyncSession, *, org_id: UUID, job_id: UUID,
    generation: int, now: datetime,
) -> tuple[AttemptCustody, bool]:
    """Read exact physical pins and whether a stop is due.

    An expired lease, retired generation, completed result handoff or
    quarantined attempt requires termination even without operator stop.
    """
    job, attempt, expected, _ = await _source(
        session, org_id=org_id, job_id=job_id, generation=generation, now=now,
    )
    due = (
        attempt.state == "QUARANTINED"
        or job.attempt_generation != generation
        or job.status != "LEASED"
        or job.lease_expires is None or now >= job.lease_expires
        or job.attempt_deadline is None or now >= job.attempt_deadline
    )
    return expected, due


async def prepare_operation(
    session: AsyncSession, *, org_id: UUID, job_id: UUID, generation: int,
    actor_id: UUID, kind: str, now: datetime,
) -> AttemptCustody:
    """Commit one non-reusable intent before physical AWS IO.

    Termination is allowed after an expired lease or quarantined attachment
    as a separately controlled cleanup action, but only for journaled IDs.
    """
    if kind not in OPERATIONS:
        raise PhysicalConflict("unknown native AWS operation")
    job, attempt, expected, operations = await _source(
        session, org_id=org_id, job_id=job_id, generation=generation, now=now,
    )
    if kind in operations or "TERMINATE" in operations:
        raise PhysicalConflict("physical operation already prepared")
    if kind in ATTACH_DEVICES:
        if not _live(job, attempt, now) or attempt.state != "INSTANCE_RECORDED":
            raise PhysicalConflict("stale or quarantined lease prevents attachment")
        required = set() if kind == "ATTACH_INPUT" else {"ATTACH_INPUT"}
        if set(operations) != required or any(
            item.state != "VERIFIED" for item in operations.values()
        ):
            raise PhysicalConflict("physical attachment order or state mismatch")
    # TERMINATE cannot be prepared while a prior attachment call remains
    # PREPARED. Ambiguity must first be marked UNKNOWN, for reconciliation.
    elif any(item.state == "PREPARED" for item in operations.values()):
        raise PhysicalConflict("unresolved physical call before termination")
    volume_id = (
        expected.input_volume_id if kind == "ATTACH_INPUT" else
        expected.output_volume_id if kind == "ATTACH_OUTPUT" else None
    )
    session.add(GuestPhysicalOperation(
        org_id=org_id, job_id=job_id, generation=generation,
        kind=kind, instance_id=expected.instance_id, volume_id=volume_id,
        state="PREPARED", created_at=now, updated_at=now,
    ))
    await session.flush()
    await record_event(
        session, org_id=org_id, actor_id=actor_id, stream="scan",
        event_type="GUEST_PHYSICAL_OPERATION_PREPARED",
        body={"job_id": str(job_id), "generation": generation, "kind": kind},
    )
    return expected


async def record_operation(
    session: AsyncSession, *, org_id: UUID, job_id: UUID, generation: int,
    actor_id: UUID, kind: str, expected: AttemptCustody,
    now: datetime,
) -> str:
    """Record independently verified attach or accepted termination request.

    A TERMINATE response is only REQUESTED, never proof of detachment.
    """
    if kind not in OPERATIONS:
        raise PhysicalConflict("unknown native AWS operation")
    job, attempt, current, ops = await _source(
        session, org_id=org_id, job_id=job_id, generation=generation, now=now,
    )
    op = ops.get(kind)
    if op is None or op.state != "PREPARED" or current != expected:
        raise PhysicalConflict("missing, stale or mutated physical operation")
    if now < op.updated_at:
        raise PhysicalConflict("physical operation time rollback")
    if kind == "TERMINATE":
        op.state = "REQUESTED"
    elif _live(job, attempt, now) and attempt.state == "INSTANCE_RECORDED":
        op.state = "VERIFIED"
    else:
        op.state = "UNKNOWN"
        attempt.state, attempt.updated_at = "QUARANTINED", now
    op.updated_at = now
    await record_event(
        session, org_id=org_id, actor_id=actor_id, stream="scan",
        event_type="GUEST_PHYSICAL_OPERATION_RECORDED",
        body={
            "job_id": str(job_id), "generation": generation,
            "kind": kind, "state": op.state,
        },
    )
    return op.state


async def mark_operation_unknown(
    session: AsyncSession, *, org_id: UUID, job_id: UUID, generation: int,
    actor_id: UUID, kind: str, now: datetime,
) -> None:
    """Quarantine a timeout/ambiguous AWS result without replaying the call."""
    if kind not in OPERATIONS:
        raise PhysicalConflict("unknown native AWS operation")
    _, attempt = await _locked(session, org_id, job_id, generation)
    _clock(now)
    op = await session.scalar(select(GuestPhysicalOperation).where(
        GuestPhysicalOperation.org_id == org_id,
        GuestPhysicalOperation.job_id == job_id,
        GuestPhysicalOperation.generation == generation,
        GuestPhysicalOperation.kind == kind,
    ).with_for_update())
    if (
        op is None or op.state != "PREPARED" or now < op.updated_at
        or now < attempt.updated_at or attempt.state == "DISPOSED"
    ):
        raise PhysicalConflict("physical operation cannot be marked UNKNOWN")
    op.state, op.updated_at = "UNKNOWN", now
    attempt.state, attempt.updated_at = "QUARANTINED", now
    await record_event(
        session, org_id=org_id, actor_id=actor_id, stream="scan",
        event_type="GUEST_PHYSICAL_OPERATION_UNKNOWN",
        body={"job_id": str(job_id), "generation": generation, "kind": kind},
    )
