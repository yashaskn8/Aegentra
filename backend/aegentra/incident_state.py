"""Revision-fenced incident triage. Browser operators cannot declare containment.

Only these two transitions are exposed through the case API:
OPEN -> TRIAGED -> CONTAINMENT_REQUESTED.
The remaining SA-1.1 states require separate privileged, independently
validated containment and recovery evidence; they are not UI toggles.
"""
from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegentra.audit import record_event
from aegentra.db import CaseMembership, InvestigationCase


class IncidentUnavailable(ValueError):
    pass


class IncidentConflict(ValueError):
    pass


class IncidentRevisionConflict(IncidentConflict):
    pass


_OPERATOR_TRANSITIONS = {
    ("OPEN", "TRIAGED"),
    ("TRIAGED", "CONTAINMENT_REQUESTED"),
}


async def request_incident_transition(
    session: AsyncSession, *,
    org_id: UUID, identity_id: UUID, case_id: UUID,
    next_status: str, expected_revision: int,
) -> dict:
    if next_status not in {"TRIAGED", "CONTAINMENT_REQUESTED"}:
        raise IncidentConflict("independent containment authority required")
    if expected_revision <= 0:
        raise IncidentConflict("case revision must be positive")

    # Lock the case, then check a current database membership grant.
    case = await session.scalar(
        select(InvestigationCase).where(
            InvestigationCase.org_id == org_id,
            InvestigationCase.id == case_id,
        ).with_for_update()
    )
    membership = await session.scalar(
        select(CaseMembership).where(
            CaseMembership.org_id == org_id,
            CaseMembership.case_id == case_id,
            CaseMembership.identity_id == identity_id,
        )
    )
    if case is None or membership is None or membership.grant_type not in {
        "OWNER", "ANALYST",
    }:
        raise IncidentUnavailable("incident case unavailable")
    if case.revision != expected_revision:
        raise IncidentRevisionConflict("stale incident revision")
    if (case.status, next_status) not in _OPERATOR_TRANSITIONS:
        raise IncidentConflict("transition is not an authorized incident step")

    case.status = next_status
    case.revision += 1
    await record_event(
        session, org_id=org_id, actor_id=identity_id,
        event_type="INCIDENT_" + next_status,
        stream="cases",
        body={
            "case_id": str(case_id), "asset_id": str(case.asset_id),
            "revision": case.revision,
            "effect": "REQUEST_ONLY",
            "new_status": next_status,
        },
    )
    return {
        "id": str(case.id), "asset_id": str(case.asset_id),
        "status": case.status, "revision": case.revision,
        "enforcement_effect": "NONE",
    }
