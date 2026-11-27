"""Authorized, keyset-paginated projection of retained case audit events."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import and_, or_, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from aegentra.audit_reconcile import AuditGap, read_audit_payload_v2
from aegentra.case_contracts import CaseTimelineEvent, CaseTimelineKind, CaseTimelinePage
from aegentra.case_store import CaseNotFound, accessible_case
from aegentra.db import AuditEntry, CaseEvidence, CaseMembership, InvestigationCase


TIMELINE_CURSOR_LIMIT = 300


class InvalidTimelineCursor(ValueError):
    pass


def encode_timeline_cursor(
    org_id: UUID, case_id: UUID, evidence_id: UUID | None, occurred_at: datetime, event_hash: bytes,
) -> str:
    when = occurred_at.astimezone(timezone.utc).isoformat(timespec="microseconds")
    value = f"v1|{org_id.hex}|{case_id.hex}|{evidence_id.hex if evidence_id else '-'}|{when}|{event_hash.hex()}"
    return base64.urlsafe_b64encode(value.encode("ascii")).decode("ascii").rstrip("=")


def decode_timeline_cursor(
    cursor: str, org_id: UUID, case_id: UUID, evidence_id: UUID | None,
) -> tuple[datetime, bytes]:
    try:
        if not 1 <= len(cursor) <= TIMELINE_CURSOR_LIMIT:
            raise ValueError("cursor size")
        raw = base64.b64decode(cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True)
        _, _, _, _, when, encoded_hash = raw.decode("ascii").split("|")
        occurred_at, event_hash = datetime.fromisoformat(when), bytes.fromhex(encoded_hash)
        if (
            occurred_at.utcoffset() is None or len(event_hash) != 32
            or encode_timeline_cursor(org_id, case_id, evidence_id, occurred_at, event_hash) != cursor
        ):
            raise ValueError("cursor scope or shape")
        return occurred_at, event_hash
    except (ValueError, OverflowError) as exc:
        raise InvalidTimelineCursor("invalid timeline cursor") from exc


def _project_event(entry: AuditEntry, asset_id: UUID) -> CaseTimelineEvent:
    body = read_audit_payload_v2(entry)
    case_ref, evidence_ref = entry.timeline_case_id, entry.timeline_evidence_id
    if case_ref is None or body.get("case_id") != str(case_ref):
        raise AuditGap("case timeline scope differs from the retained event")
    if "asset_id" in body and body["asset_id"] != str(asset_id):
        raise AuditGap("case timeline asset differs from the retained event")
    if entry.event_type == "CASE_EVIDENCE_LINKED" and (
        evidence_ref is None or body.get("evidence_id") != str(evidence_ref)
    ):
        raise AuditGap("case timeline evidence differs from the retained event")
    revision = None
    if entry.event_type.startswith("INCIDENT_"):
        field = "case_revision" if entry.event_type == "INCIDENT_CONTAINMENT_VERIFIED" else "revision"
        value = body.get(field)
        if type(value) is not int or not 1 <= value <= 2147483647:
            raise AuditGap("case timeline revision is missing or invalid")
        revision = value
    try:
        return CaseTimelineEvent(
            id=entry.event_hash.hex(), occurred_at=entry.created_at,
            kind=CaseTimelineKind(entry.event_type), evidence_id=evidence_ref, revision=revision,
        )
    except ValueError as exc:
        raise AuditGap("case timeline record is invalid") from exc


async def list_case_timeline(
    session: AsyncSession, *, org_id: UUID, identity_id: UUID, case_id: UUID,
    evidence_id: UUID | None = None, cursor: str | None = None, page_size: int = 50,
) -> CaseTimelinePage:
    case = await accessible_case(session, org_id=org_id, identity_id=identity_id, case_id=case_id)
    if evidence_id is not None and await session.get(
        CaseEvidence, (org_id, case.asset_id, case_id, evidence_id),
    ) is None:
        raise CaseNotFound("evidence unavailable")
    if not 1 <= page_size <= 100:
        raise ValueError("page size outside allowed range")

    membership = select(1).select_from(CaseMembership).join(
        InvestigationCase,
        and_(InvestigationCase.org_id == CaseMembership.org_id, InvestigationCase.id == CaseMembership.case_id),
    ).where(
        CaseMembership.org_id == org_id, CaseMembership.case_id == case_id,
        CaseMembership.identity_id == identity_id, InvestigationCase.asset_id == case.asset_id,
    )
    current_link = select(CaseEvidence.evidence_id).where(
        CaseEvidence.org_id == org_id, CaseEvidence.asset_id == case.asset_id,
        CaseEvidence.case_id == case_id, CaseEvidence.evidence_id == AuditEntry.timeline_evidence_id,
    ).exists()
    query = select(AuditEntry).where(
        AuditEntry.org_id == org_id, AuditEntry.timeline_case_id == case_id,
        membership.exists(), or_(AuditEntry.timeline_evidence_id.is_(None), current_link),
        or_(AuditEntry.event_type != "INCIDENT_CONTAINMENT_VERIFIED", membership.where(
            InvestigationCase.status.in_(("CONTAINED", "RECOVERING", "CLOSED")),
        ).exists()),
    ).order_by(AuditEntry.created_at, AuditEntry.event_hash).limit(page_size + 1)
    if evidence_id is not None:
        query = query.where(AuditEntry.timeline_evidence_id == evidence_id)
    if cursor is not None:
        when, event_hash = decode_timeline_cursor(cursor, org_id, case_id, evidence_id)
        query = query.where(tuple_(AuditEntry.created_at, AuditEntry.event_hash) > tuple_(when, event_hash))

    entries = list((await session.scalars(query)).all())
    if not entries:
        # An empty page can also mean the grant was removed between the two reads.
        await accessible_case(session, org_id=org_id, identity_id=identity_id, case_id=case_id)
        if evidence_id is not None and await session.get(
            CaseEvidence, (org_id, case.asset_id, case_id, evidence_id), populate_existing=True,
        ) is None:
            raise CaseNotFound("evidence unavailable")
    page = entries[:page_size]
    next_cursor = None
    if len(entries) > page_size:
        last = page[-1]
        next_cursor = encode_timeline_cursor(org_id, case_id, evidence_id, last.created_at, last.event_hash)
    return CaseTimelinePage(items=[_project_event(entry, case.asset_id) for entry in page], next_cursor=next_cursor)
