"""Case-scoped investigation access: no globally readable evidence by ID.

Membership grants are evaluated at the database boundary on every operation.
No unverified user can create or link evidence bytes through this module.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from aegentra.audit import IdempotencyConflict, canonical_bytes, record_event
from aegentra.db import (
    Asset, CaseEvidence, CaseMembership, Evidence, IdempotencyRequest,
    InvestigationCase,
)


class CaseNotFound(Exception):
    pass


async def accessible_case(
    session: AsyncSession, *,
    org_id: UUID, identity_id: UUID, case_id: UUID,
    require_write: bool = False,
) -> InvestigationCase:
    row = await session.execute(
        select(InvestigationCase, CaseMembership)
        .join(
            CaseMembership,
            (CaseMembership.org_id == InvestigationCase.org_id)
            & (CaseMembership.case_id == InvestigationCase.id),
        )
        .where(
            InvestigationCase.org_id == org_id,
            InvestigationCase.id == case_id,
            CaseMembership.identity_id == identity_id,
        )
    )
    pair = row.one_or_none()
    if pair is None or (require_write and pair[1].grant_type not in {"OWNER", "ANALYST"}):
        raise CaseNotFound("case unavailable")
    return pair[0]


async def list_member_cases(
    session: AsyncSession, *, org_id: UUID, identity_id: UUID
) -> list[InvestigationCase]:
    rows = await session.scalars(
        select(InvestigationCase)
        .join(
            CaseMembership,
            (CaseMembership.org_id == InvestigationCase.org_id)
            & (CaseMembership.case_id == InvestigationCase.id),
        )
        .where(
            InvestigationCase.org_id == org_id,
            CaseMembership.identity_id == identity_id,
        )
        .order_by(InvestigationCase.created_at, InvestigationCase.id)
        .limit(101)
    )
    return list(rows.all())


async def register_case(
    session: AsyncSession, *, org_id: UUID, identity_id: UUID,
    key: str, asset_id: UUID, title: str,
) -> dict:
    route = "POST /v1/cases"
    request_hash = hashlib.sha256(
        canonical_bytes({"asset_id": str(asset_id), "title": title})
    ).digest()

    await session.execute(
        pg_insert(IdempotencyRequest)
        .values(
            org_id=org_id, identity_id=identity_id, route=route, key=key,
            request_hash=request_hash, response={}, status=0,
            created_at=datetime.now(timezone.utc),
        )
        .on_conflict_do_nothing(
            index_elements=["org_id", "identity_id", "route", "key"]
        )
    )
    request = await session.scalar(
        select(IdempotencyRequest)
        .where(
            IdempotencyRequest.org_id == org_id,
            IdempotencyRequest.identity_id == identity_id,
            IdempotencyRequest.route == route,
            IdempotencyRequest.key == key,
        ).with_for_update()
    )
    if request is None or request.request_hash != request_hash:
        raise IdempotencyConflict("idempotency key reused with different case input")
    if request.status == 201:
        return dict(request.response)
    if request.status != 0:
        raise IdempotencyConflict("unknown case request state")

    asset = await session.scalar(
        select(Asset.id).where(Asset.org_id == org_id, Asset.id == asset_id)
    )
    if asset is None:
        raise CaseNotFound("asset unavailable")

    case = InvestigationCase(
        org_id=org_id, asset_id=asset_id, title=title,
        created_by=identity_id, status="OPEN", revision=1,
        created_at=datetime.now(timezone.utc),
    )
    session.add(case)
    await session.flush()
    session.add(
        CaseMembership(
            org_id=org_id, case_id=case.id, identity_id=identity_id,
            grant_type="OWNER",
        )
    )
    result = {
        "id": str(case.id), "asset_id": str(asset_id), "title": title,
        "status": "OPEN", "revision": 1,
    }
    await record_event(
        session, org_id=org_id, actor_id=identity_id,
        event_type="CASE_CREATED", stream="cases",
        body={"case_id": str(case.id), "asset_id": str(asset_id)},
    )
    request.status = 201
    request.response = result
    return result


async def link_evidence(
    session: AsyncSession, *, org_id: UUID, identity_id: UUID,
    case_id: UUID, evidence_id: UUID,
) -> dict:
    case = await accessible_case(
        session, org_id=org_id, identity_id=identity_id,
        case_id=case_id, require_write=True,
    )
    if case.status != "OPEN":
        raise CaseNotFound("case not open")
    evidence = await session.scalar(
        select(Evidence).where(
            Evidence.org_id == org_id,
            Evidence.asset_id == case.asset_id,
            Evidence.id == evidence_id,
        )
    )
    if evidence is None:
        raise CaseNotFound("evidence unavailable for case")

    session.add(CaseEvidence(
        org_id=org_id, asset_id=case.asset_id, case_id=case_id,
        evidence_id=evidence_id, linked_by=identity_id,
        linked_at=datetime.now(timezone.utc),
    ))
    await session.flush()
    await record_event(
        session, org_id=org_id, actor_id=identity_id,
        event_type="CASE_EVIDENCE_LINKED", stream="cases",
        body={"case_id": str(case_id), "evidence_id": str(evidence_id)},
    )
    return {"case_id": str(case_id), "evidence_id": str(evidence_id)}


async def evidence_metadata(
    session: AsyncSession, *, org_id: UUID, identity_id: UUID,
    case_id: UUID, evidence_id: UUID,
) -> dict:
    case = await accessible_case(
        session, org_id=org_id, identity_id=identity_id, case_id=case_id,
    )
    evidence = await session.scalar(
        select(Evidence)
        .join(
            CaseEvidence,
            (CaseEvidence.org_id == Evidence.org_id)
            & (CaseEvidence.asset_id == Evidence.asset_id)
            & (CaseEvidence.evidence_id == Evidence.id),
        )
        .where(
            CaseEvidence.org_id == org_id,
            CaseEvidence.case_id == case_id,
            CaseEvidence.asset_id == case.asset_id,
            Evidence.id == evidence_id,
        )
    )
    if evidence is None:
        raise CaseNotFound("evidence unavailable for case")
    return {
        "id": str(evidence.id), "kind": evidence.kind,
        "sha256": evidence.digest.hex(),
        "case_id": str(case_id),
    }
