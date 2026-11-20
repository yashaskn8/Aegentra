"""Native guest cleanup proof: time-separated AWS inventory, no optimistic ACK.

Physical EC2/EBS identifiers remain in the committed guest_resource journal
after disposal. A terminated guest and two deleted raw volumes are necessary,
but independently verified cloud/IAM isolation remains a separate P0.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegentra.audit import record_event
from aegentra.db import GuestAttempt, GuestResource, ScanReceipt


class DisposalRejected(ValueError):
    pass


@dataclass(frozen=True)
class DeletedInventory:
    account_id: str
    observed_at: datetime
    instance_id: str
    instance_state: Literal["terminated", "not-found"]
    volume_states: dict[str, Literal["not-found"]]


def verify_disposal(
    *,
    account_id: str, instance_id: str,
    input_volume_id: str, output_volume_id: str,
    first: DeletedInventory, second: DeletedInventory,
    now: datetime,
) -> None:
    if any(d.tzinfo is None or d.utcoffset() is None for d in (
        first.observed_at, second.observed_at, now,
    )):
        raise DisposalRejected("trusted UTC clocks are missing")
    start = first.observed_at.astimezone(timezone.utc)
    end = second.observed_at.astimezone(timezone.utc)
    trusted = now.astimezone(timezone.utc)
    if (
        start > end
        or end - start < timedelta(seconds=30)
        or end - start > timedelta(minutes=5)
        or end > trusted
        or trusted - end > timedelta(seconds=60)
        or input_volume_id == output_volume_id
    ):
        raise DisposalRejected("disposal inventories are stale or not independently spaced")
    for snapshot in (first, second):
        if (
            snapshot.account_id != account_id
            or snapshot.instance_id != instance_id
            or snapshot.instance_state not in {"terminated", "not-found"}
            or snapshot.volume_states != {
                input_volume_id: "not-found",
                output_volume_id: "not-found",
            }
        ):
            raise DisposalRejected("EC2/EBS resources still exist or inventory differs")


async def record_verified_disposal(
    session: AsyncSession, *,
    org_id: UUID, job_id: UUID, generation: int,
    actor_id: UUID, first: DeletedInventory,
    second: DeletedInventory, now: datetime,
) -> str:
    attempt = await session.scalar(
        select(GuestAttempt).where(
            GuestAttempt.org_id == org_id, GuestAttempt.job_id == job_id,
            GuestAttempt.generation == generation,
        ).with_for_update()
    )
    if attempt is None or attempt.state not in {"DETACHED_VERIFIED", "DISPOSED"}:
        raise DisposalRejected("guest is not eligible for verified disposal")
    receipt = await session.scalar(
        select(ScanReceipt).where(
            ScanReceipt.org_id == org_id,
            ScanReceipt.job_id == job_id,
            ScanReceipt.generation == generation,
        )
    )
    if receipt is None:
        raise DisposalRejected("trusted advisory receipt must exist before disposal")
    resources = list((await session.scalars(
        select(GuestResource).where(
            GuestResource.org_id == org_id, GuestResource.job_id == job_id,
            GuestResource.generation == generation,
        )
    )).all())
    by_kind = {item.kind: item.resource_id for item in resources}
    if (
        len(resources) != 3
        or set(by_kind) != {"INSTANCE", "INPUT_EBS", "OUTPUT_EBS"}
    ):
        raise DisposalRejected("incomplete immutable physical resource ledger")
    verify_disposal(
        account_id=attempt.account_id,
        instance_id=by_kind["INSTANCE"],
        input_volume_id=by_kind["INPUT_EBS"],
        output_volume_id=by_kind["OUTPUT_EBS"],
        first=first, second=second, now=now,
    )
    if attempt.state == "DISPOSED":
        return "DISPOSED"
    attempt.state = "DISPOSED"
    attempt.updated_at = now
    await record_event(
        session, org_id=org_id, actor_id=actor_id, stream="scan",
        event_type="GUEST_PHYSICAL_DISPOSAL_VERIFIED",
        body={"job_id": str(job_id), "generation": generation},
    )
    return "DISPOSED"
