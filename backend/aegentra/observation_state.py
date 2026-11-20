"""Serialized independent observation handling and overdue HOLD policy.

Fresh current mismatches trigger STOP_SERVING. A mismatched historical
revision creates evidence but cannot stop a healthy new revision. Missing
current readback causes HOLD_PROMOTION, not an invented clean verdict.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from aegentra.audit import record_event
from aegentra.db import (
    ReleaseGrant, ReleaseObservation, ReleaseOrgGuard, ReleasePublication,
    ReleaseTarget,
)
from aegentra.observation_crypto import (
    ObserverCredential, ObservationRejected, SignedObservation,
    verify_observation,
)


async def _guarded_target(
    session: AsyncSession, org_id: UUID, target_id: UUID
) -> tuple[ReleaseOrgGuard, ReleaseTarget]:
    # Root FOR SHARE needs SELECT only; it conflicts with authority FOR UPDATE.
    # Fixed lock order remains root then target.
    root = await session.scalar(
        select(ReleaseOrgGuard).where(
            ReleaseOrgGuard.org_id == org_id
        ).with_for_update(read=True)
    )
    if root is None:
        raise ObservationRejected("installation root unavailable")
    target = await session.scalar(
        select(ReleaseTarget).where(
            ReleaseTarget.org_id == org_id,
            ReleaseTarget.id == target_id,
        ).with_for_update()
    )
    if target is None:
        raise ObservationRejected("target unavailable")
    return root, target


async def _restrict(
    session: AsyncSession, *,
    org_id: UUID, target: ReleaseTarget, new_guard: str,
) -> None:
    if target.guard == "STOP_SERVING":
        return
    if target.guard == "HOLD_PROMOTION" and new_guard == "HOLD_PROMOTION":
        return
    target.guard = new_guard
    target.epoch += 1
    # The epoch is also checked at redemption and publication; cancellation
    # prevents an old, still-open grant from being accidentally accepted.
    await session.execute(
        update(ReleaseGrant).where(
            ReleaseGrant.org_id == org_id,
            ReleaseGrant.target_id == target.id,
            ReleaseGrant.status == "GRANTED",
        ).values(status="CANCELED")
    )


async def record_observation(
    session: AsyncSession, *,
    envelope: SignedObservation, observer: ObserverCredential,
    actor_id: UUID, now: datetime,
) -> str:
    body = verify_observation(envelope, observer=observer, now=now)
    root, target = await _guarded_target(session, body.org_id, body.target_id)
    if (
        body.incarnation != root.incarnation
        or body.host != target.destination_host
        or body.resource_path != target.resource_path
        or target.mode != "ENFORCED"
        or body.measured_at > now + timedelta(seconds=30)
    ):
        raise ObservationRejected("observation is outside qualified enrollment")
    if await session.scalar(
        select(ReleaseObservation.id).where(
            ReleaseObservation.org_id == body.org_id,
            ReleaseObservation.id == body.observation_id,
        )
    ):
        raise ObservationRejected("observation ID is already consumed")

    pub = await session.scalar(
        select(ReleasePublication).where(
            ReleasePublication.org_id == body.org_id,
            ReleasePublication.target_id == body.target_id,
            ReleasePublication.published_revision == body.published_revision,
        )
    )
    if (
        pub is None
        or pub.status != "SEALED"
        or pub.attempt_sequence != body.attempt_sequence
        or pub.representation_sha256.hex() != body.expected_sha256
        or pub.delivery_profile_sha256.hex() != body.expected_profile_sha256
    ):
        raise ObservationRejected("observed expected release does not match sealed history")

    # Even a properly signed delayed measurement must not stop a newly
    # published revision. Restrict current only if measured after publication.
    historical = (
        body.published_revision != target.published_revision
        or body.attempt_sequence != target.published_attempt_sequence
        or body.measured_at < pub.created_at
        or now - body.measured_at > timedelta(seconds=60)
    )
    matching = (
        body.http_status == 200 and body.complete_bytes
        and body.observed_sha256 == body.expected_sha256
        and body.observed_profile_sha256 == body.expected_profile_sha256
    )
    if historical:
        disposition = "HISTORICAL"
        event_type = "HISTORICAL_READBACK_RECORDED"
    elif matching:
        disposition = "MATCH"
        event_type = "CURRENT_READBACK_MATCH"
    elif body.http_status == 200 and body.complete_bytes:
        disposition = "CURRENT_MISMATCH"
        event_type = "CURRENT_READBACK_MISMATCH_STOP"
        await _restrict(
            session, org_id=body.org_id, target=target,
            new_guard="STOP_SERVING",
        )
    else:
        disposition = "COVERAGE_GAP"
        event_type = "CURRENT_READBACK_GAP_HOLD"
        await _restrict(
            session, org_id=body.org_id, target=target,
            new_guard="HOLD_PROMOTION",
        )

    session.add(ReleaseObservation(
        org_id=body.org_id, id=body.observation_id,
        target_id=body.target_id, incarnation=body.incarnation,
        published_revision=body.published_revision,
        attempt_sequence=body.attempt_sequence,
        observer_key_id=body.observer_key_id, cohort=body.cohort,
        expected_sha256=bytes.fromhex(body.expected_sha256),
        observed_sha256=bytes.fromhex(body.observed_sha256),
        expected_profile_sha256=bytes.fromhex(body.expected_profile_sha256),
        observed_profile_sha256=bytes.fromhex(body.observed_profile_sha256),
        http_status=body.http_status, complete_bytes=body.complete_bytes,
        disposition=disposition, signed_body=body.model_dump(mode="json"),
        signature=envelope.signature_der, measured_at=body.measured_at,
        recorded_at=now,
    ))
    await session.flush()
    await record_event(
        session, org_id=body.org_id, actor_id=actor_id, stream="release",
        event_type=event_type,
        body={
            "target_id": str(body.target_id),
            "observation_id": str(body.observation_id),
            "published_revision": body.published_revision,
            "disposition": disposition,
        },
    )
    return disposition


async def hold_if_observation_overdue(
    session: AsyncSession, *,
    org_id: UUID, target_id: UUID,
    actor_id: UUID, now: datetime,
    max_delay: timedelta = timedelta(minutes=5),
) -> bool:
    """Require a current matching signed readback before five-minute deadline."""
    if (
        now.tzinfo is None or now.utcoffset() is None
        or not timedelta(seconds=30) <= max_delay <= timedelta(hours=1)
    ):
        raise ObservationRejected("invalid observation deadline")
    root, target = await _guarded_target(session, org_id, target_id)
    if target.mode != "ENFORCED" or target.guard != "ACTIVE":
        return False
    current = await session.scalar(
        select(ReleasePublication).where(
            ReleasePublication.org_id == org_id,
            ReleasePublication.target_id == target_id,
            ReleasePublication.published_revision == target.published_revision,
        )
    )
    if current is None or now < current.created_at + max_delay:
        return False

    healthy = await session.scalar(
        select(ReleaseObservation.id).where(
            ReleaseObservation.org_id == org_id,
            ReleaseObservation.target_id == target_id,
            ReleaseObservation.published_revision == target.published_revision,
            ReleaseObservation.attempt_sequence == target.published_attempt_sequence,
            ReleaseObservation.disposition == "MATCH",
            ReleaseObservation.measured_at >= current.created_at,
        ).limit(1)
    )
    if healthy is not None:
        return False
    await _restrict(
        session, org_id=org_id, target=target,
        new_guard="HOLD_PROMOTION",
    )
    await record_event(
        session, org_id=org_id, actor_id=actor_id, stream="release",
        event_type="CURRENT_OBSERVATION_OVERDUE_HOLD",
        body={
            "target_id": str(target_id),
            "published_revision": target.published_revision,
        },
    )
    return True
