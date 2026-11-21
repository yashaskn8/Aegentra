"""Default-disabled native EBS attachment and EC2 termination adapter.

All cloud writes happen after a committed, irreversible physical intent and
outside DB locks. Failed or ambiguous operations quarantine the attempt.
No guest execution, no raw device mount/read, and no production qualification.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegentra.bridge_custody import AttemptCustody, CustodyError
from aegentra.guest_physical_operations import (
    ATTACH_DEVICES, load_operation_state, mark_operation_unknown,
    prepare_operation, record_operation,
)
from aegentra.native_attachment_inventory import (
    collect_live_inventory, verify_attachment_count, verify_termination_inventory,
)
from aegentra.persistence import organization_session


class PhysicalUnknown(RuntimeError):
    """AWS outcome requires independently audited reconciliation, not replay."""


Clock = Callable[[], datetime]


def _attach_response(response: Any, expected: AttemptCustody, kind: str) -> None:
    volume_id = (
        expected.input_volume_id if kind == "ATTACH_INPUT" else expected.output_volume_id
    )
    if (
        not isinstance(response, dict)
        or response.get("VolumeId") != volume_id
        or response.get("InstanceId") != expected.instance_id
        or response.get("Device") != ATTACH_DEVICES[kind]
        or response.get("State") not in {"attaching", "attached"}
    ):
        raise CustodyError("untrusted AWS EBS attachment response")


def _termination_response(response: Any, expected: AttemptCustody) -> None:
    if not isinstance(response, dict):
        raise CustodyError("untrusted AWS termination receipt")
    items = response.get("TerminatingInstances")
    if (
        not isinstance(items, list) or len(items) != 1
        or not isinstance(items[0], dict)
        or items[0].get("InstanceId") != expected.instance_id
        or not isinstance(items[0].get("CurrentState"), dict)
        or items[0]["CurrentState"].get("Name") not in {
            "shutting-down", "terminated",
        }
    ):
        raise CustodyError("AWS termination result is not for the pinned instance")


async def _unknown(
    *, sessions: async_sessionmaker[AsyncSession],
    expected: AttemptCustody, org_id: UUID, actor_id: UUID,
    kind: str, clock: Clock,
) -> None:
    try:
        async with organization_session(sessions, org_id) as session:
            await mark_operation_unknown(
                session, org_id=org_id, job_id=expected.job_id,
                generation=expected.generation, actor_id=actor_id,
                kind=kind, now=clock(),
            )
    except Exception as exc:
        raise PhysicalUnknown(
            "physical outcome unknown and quarantine journal unavailable"
        ) from exc


async def attach_raw_volumes(
    *, sessions: async_sessionmaker[AsyncSession], ec2: Any, sts: Any,
    org_id: UUID, job_id: UUID, generation: int, actor_id: UUID,
    explicitly_enabled: bool = False,
    clock: Clock = lambda: datetime.now(timezone.utc),
) -> str:
    """Attach input then output, one call each, with fresh AWS readback.

    Success means AWS inventory matches two raw EBS attachments; it never
    indicates the guest has executed, received safe input, or passed isolation.
    """
    if not explicitly_enabled:
        raise PermissionError("live AWS physical attachment disabled")
    async with organization_session(sessions, org_id) as session:
        expected, due = await load_operation_state(
            session, org_id=org_id, job_id=job_id, generation=generation,
            now=clock(),
        )
    if due:
        raise PhysicalUnknown("lease expired or scan already requires termination")
    for index, kind in enumerate(ATTACH_DEVICES):
        before = await asyncio.to_thread(
            collect_live_inventory, ec2=ec2, sts=sts, expected=expected,
        )
        verify_attachment_count(expected=expected, observed=before, attached=index)
        async with organization_session(sessions, org_id) as session:
            prepared = await prepare_operation(
                session, org_id=org_id, job_id=job_id, generation=generation,
                actor_id=actor_id, kind=kind, now=clock(),
            )
        try:
            if prepared != expected:
                raise CustodyError("physical identity changed before AWS attach")
            result = await asyncio.to_thread(
                ec2.attach_volume,
                InstanceId=expected.instance_id,
                VolumeId=(
                    expected.input_volume_id if index == 0
                    else expected.output_volume_id
                ),
                Device=ATTACH_DEVICES[kind],
            )
            _attach_response(result, expected, kind)
            after = await asyncio.to_thread(
                collect_live_inventory, ec2=ec2, sts=sts, expected=expected,
            )
            verify_attachment_count(expected=expected, observed=after, attached=index + 1)
        except (Exception, asyncio.CancelledError) as exc:
            await _unknown(
                sessions=sessions, expected=expected, org_id=org_id,
                actor_id=actor_id, kind=kind, clock=clock,
            )
            raise PhysicalUnknown(
                "AWS raw-volume attach uncertain; attempt quarantined"
            ) from exc
        try:
            async with organization_session(sessions, org_id) as session:
                status = await record_operation(
                    session, org_id=org_id, job_id=job_id,
                    generation=generation, actor_id=actor_id,
                    kind=kind, expected=expected, now=clock(),
                )
        except Exception as exc:
            raise PhysicalUnknown(
                "AWS attach verified, but durable attachment outcome is unknown"
            ) from exc
        if status != "VERIFIED":
            raise PhysicalUnknown("physical lease expired during attach; quarantined")
    return "BOTH_RAW_DEVICES_VERIFIED_NOT_GUEST_EXECUTION_AUTHORITY"


async def request_native_termination(
    *, sessions: async_sessionmaker[AsyncSession], ec2: Any, sts: Any,
    org_id: UUID, job_id: UUID, generation: int, actor_id: UUID,
    operator_stop: bool = False,
    explicitly_enabled: bool = False,
    clock: Clock = lambda: datetime.now(timezone.utc),
) -> str:
    """Request exact guest termination only when due or explicitly stopped.

    The ACK is REQUESTED, never proof of terminated EC2 or detached EBS.
    Subsequent independent two-pass detach checks remain mandatory.
    """
    if not explicitly_enabled:
        raise PermissionError("live AWS guest termination disabled")
    async with organization_session(sessions, org_id) as session:
        expected, due = await load_operation_state(
            session, org_id=org_id, job_id=job_id,
            generation=generation, now=clock(),
        )
    if not due and not operator_stop:
        raise PermissionError("termination requires deadline, revocation or operator stop")
    before = await asyncio.to_thread(
        collect_live_inventory, ec2=ec2, sts=sts, expected=expected,
    )
    verify_termination_inventory(expected=expected, observed=before)
    async with organization_session(sessions, org_id) as session:
        prepared = await prepare_operation(
            session, org_id=org_id, job_id=job_id, generation=generation,
            actor_id=actor_id, kind="TERMINATE", now=clock(),
        )
    try:
        if prepared != expected:
            raise CustodyError("guest physical identity changed before termination")
        response = await asyncio.to_thread(
            ec2.terminate_instances, InstanceIds=[expected.instance_id],
        )
        _termination_response(response, expected)
    except (Exception, asyncio.CancelledError) as exc:
        await _unknown(
            sessions=sessions, expected=expected, org_id=org_id,
            actor_id=actor_id, kind="TERMINATE", clock=clock,
        )
        raise PhysicalUnknown(
            "AWS termination uncertain; attempt quarantined"
        ) from exc
    try:
        async with organization_session(sessions, org_id) as session:
            status = await record_operation(
                session, org_id=org_id, job_id=job_id,
                generation=generation, actor_id=actor_id,
                kind="TERMINATE", expected=expected, now=clock(),
            )
    except Exception as exc:
        raise PhysicalUnknown("AWS termination requested but DB acknowledgment unknown") from exc
    if status != "REQUESTED":
        raise PhysicalUnknown("unexpected EC2 termination journal outcome")
    return "TERMINATION_REQUESTED_PENDING_INDEPENDENT_DETACH"
