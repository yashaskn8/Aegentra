"""Bounded native scan watchdog for the offline disposable EC2 attempt.

This is a default-disabled library, not a deployed daemon. It renews a
fenced lease every 30 seconds and requests exact journaled termination on
stop/expiry. It cannot certify termination, raw output, or guest isolation.
Every database transaction ends before sleeping or making AWS calls.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegentra.guest_physical_operations import heartbeat_physical_attempt
from aegentra.native_physical_controller import request_native_termination
from aegentra.persistence import organization_session


class SupervisionUnknown(RuntimeError):
    """Independent operator must reconcile the guest and its lease."""


Clock = Callable[[], datetime]
Sleeper = Callable[[float], Awaitable[None]]
TERMINATION_REQUESTED = "TERMINATION_REQUESTED_PENDING_INDEPENDENT_DETACH"


async def supervise_native_attempt(
    *, sessions: async_sessionmaker[AsyncSession],
    ec2: Any, sts: Any, org_id: UUID, job_id: UUID,
    generation: int, nonce: str, actor_id: UUID,
    explicitly_enabled: bool = False,
    clock: Clock = lambda: datetime.now(timezone.utc),
    sleep: Sleeper = asyncio.sleep,
) -> str:
    """Stop the pinned guest after fenced lease expiry or result handoff.

    No AWS call is made while a database session is held. The 20-tick
    maximum is a safety fuse, not an extension of the eight-minute job
    deadline. Interrupted workers must be independently reconciled.
    """
    if not explicitly_enabled:
        raise PermissionError("native watchdog has no live execution authority")
    if (
        not isinstance(org_id, UUID)
        or not isinstance(job_id, UUID)
        or not isinstance(actor_id, UUID)
        or type(generation) is not int or generation < 1
        or not isinstance(nonce, str) or not nonce.isascii()
        or not 32 <= len(nonce) <= 64
    ):
        raise ValueError("invalid native supervisor identity or fence")

    previous: datetime | None = None
    for _ in range(20):
        now = clock()
        if (
            not isinstance(now, datetime)
            or now.tzinfo is None or now.utcoffset() is None
            or (previous is not None and now <= previous)
        ):
            raise SupervisionUnknown("native watchdog clock stalled or reversed")
        previous = now
        try:
            async with organization_session(sessions, org_id) as session:
                status = await heartbeat_physical_attempt(
                    session, org_id=org_id, job_id=job_id,
                    generation=generation, nonce=nonce, now=now,
                )
        except Exception as exc:
            raise SupervisionUnknown(
                "native heartbeat failed; independent physical reconciliation required"
            ) from exc

        if status == "RENEWED":
            # The next heartbeat is responsible for the next lease recheck.
            # No locks or long-lived PostgreSQL transaction span this sleep.
            await sleep(30)
            continue
        if status == "RECONCILE":
            raise SupervisionUnknown(
                "pending or ambiguous physical operation requires independent reconciliation"
            )
        if status != "STOP_REQUIRED":
            raise SupervisionUnknown("unrecognized native watchdog state")
        try:
            outcome = await request_native_termination(
                sessions=sessions, ec2=ec2, sts=sts,
                org_id=org_id, job_id=job_id, generation=generation,
                actor_id=actor_id, operator_stop=True,
                explicitly_enabled=True, clock=clock,
            )
        except Exception as exc:
            raise SupervisionUnknown(
                "native guest stop request uncertain; independent reconciliation required"
            ) from exc
        if outcome != TERMINATION_REQUESTED:
            raise SupervisionUnknown("native guest stop lacked a trusted request receipt")
        return outcome

    raise SupervisionUnknown(
        "native watchdog exceeded its fixed heartbeat budget; stop is unconfirmed"
    )
