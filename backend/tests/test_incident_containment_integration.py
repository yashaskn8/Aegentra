"""Containment cannot be declared by browser; only signed native custodian."""
from __future__ import annotations

import asyncio
import hashlib
import os
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker

from aegentra.audit import record_event
from aegentra.case_timeline import list_case_timeline
from aegentra.containment_archive import ContainmentProofArchive
from test_containment_archive import FakeS3, FakeSTS
from aegentra.db import (
    Asset, AuditEntry, AuditStream, CaseMembership, Identity,
    IncidentContainmentReceipt, InvestigationCase, Organization, OutboxEvent,
    ReleaseOrgGuard, ReleaseTarget,
)
from aegentra.incident_containment import (
    ContainmentArchiveRef, ContainmentStateRejected,
    containment_proof_bytes, record_independent_containment,
)
from aegentra.persistence import make_engine, organization_session
from aegentra.release_state import release_session
from test_stop_containment import fixture as signed_stop_fixture


@pytest.mark.skipif(
    not all(os.getenv(name) for name in (
        "AEGENTRA_TEST_ADMIN_URL", "AEGENTRA_TEST_APP_URL",
        "AEGENTRA_TEST_INCIDENT_URL",
    )),
    reason="distinct native incident-custody PostgreSQL role not configured",
)
def test_only_independent_signed_containment_can_advance_incident() -> None:
    asyncio.run(_exercise())


async def _exercise() -> None:
    admin = make_engine(os.environ["AEGENTRA_TEST_ADMIN_URL"])
    app = make_engine(os.environ["AEGENTRA_TEST_APP_URL"])
    incident = make_engine(os.environ["AEGENTRA_TEST_INCIDENT_URL"])
    factory = async_sessionmaker(incident, expire_on_commit=False)
    evidence, _ = signed_stop_fixture()
    root = evidence["root"]
    org, target, incarnation = root.org_id, evidence["target_id"], root.incarnation
    case_id, asset, actor = uuid4(), uuid4(), uuid4()
    now = evidence["now"]
    root_version = "independent-security-root-v8"
    raw = containment_proof_bytes(
        root=root, root_version_id=root_version,
        authority_fence=evidence["authority_fence"],
        gateway_acks=evidence["gateway_acks"],
    )
    independent_archive = ContainmentProofArchive(
        s3=FakeS3(), sts=FakeSTS(), bucket="security-incidents",
        security_account_id="123456789012",
    )
    archived = independent_archive.append(
        org_id=org, case_id=case_id,
        generation=root.veto_generation, canonical_proof=raw,
    )
    retrieved = independent_archive.read_exact(
        archived, org_id=org, case_id=case_id,
        generation=root.veto_generation,
    )
    args = dict(
        org_id=org, case_id=case_id, target_id=target,
        actor_id=actor, expected_revision=3,
        root=root, root_version_id=root_version,
        authority_fence=evidence["authority_fence"],
        authority_key=evidence["authority_key"],
        gateway_acks=evidence["gateway_acks"],
        enrolled_gateways=evidence["enrolled_gateways"],
        archive_ref=archived, exact_archive_bytes=retrieved,
        pinned_archive_bucket="security-incidents", now=now,
    )
    try:
        async with admin.begin() as s:
            await s.execute(insert(Organization).values(
                id=org, slug=f"incident-{org.hex}",
            ))
            await s.execute(insert(Identity).values(
                id=actor, org_id=org, issuer="https://idp.example.test",
                subject="independent-incident-owner", role="ANALYST",
                active=True, membership_version=1,
            ))
            await s.execute(insert(Asset).values(
                org_id=org, id=asset, slug="protected-static", criticality="HIGH",
            ))
            await s.execute(insert(ReleaseOrgGuard).values(
                org_id=org, incarnation=incarnation, epoch=2,
            ))
            await s.execute(insert(ReleaseTarget).values(
                org_id=org, id=target, asset_id=asset,
                destination_host="static.example.test",
                resource_path="/index.html", mode="ENFORCED",
                guard="STOP_SERVING", epoch=4,
                published_revision=0, next_attempt_sequence=0,
            ))
            await s.execute(insert(InvestigationCase).values(
                org_id=org, id=case_id, asset_id=asset,
                title="Signed STOP fixture", created_by=actor,
                status="CONTAINMENT_REQUESTED", revision=3,
                created_at=now,
            ))
            await s.execute(insert(CaseMembership).values(
                org_id=org, case_id=case_id, identity_id=actor,
                grant_type="OWNER",
            ))

        # Even valid same-org browser DB credentials may not forge CONTAINED.
        with pytest.raises(DBAPIError, match="independent incident custody"):
            async with organization_session(async_sessionmaker(app), org) as s:
                await s.execute(
                    update(InvestigationCase)
                    .where(
                        InvestigationCase.org_id == org,
                        InvestigationCase.id == case_id,
                    ).values(status="CONTAINED", revision=4)
                )

        with pytest.raises(DBAPIError, match="independent incident custody"):
            async with organization_session(async_sessionmaker(app), org) as s:
                await record_event(
                    s, org_id=org, actor_id=actor, stream="cases", event_type="INCIDENT_CONTAINMENT_VERIFIED",
                    body={"case_id": str(case_id), "case_revision": 4},
                )

        # A missing gateway ACK cannot become a case containment success.
        with pytest.raises(ContainmentStateRejected):
            async with release_session(factory, org) as s:
                await record_independent_containment(s, **{
                    **args, "gateway_acks": args["gateway_acks"][:1],
                })

        # Even an exact version reference cannot substitute for a different
        # byte stream than the immutable S3 record.
        with pytest.raises(ContainmentStateRejected):
            async with release_session(factory, org) as s:
                await record_independent_containment(
                    s, **{**args, "exact_archive_bytes": retrieved + b"x"}
                )

        async with release_session(factory, org) as s:
            assert await record_independent_containment(s, **args) == "CONTAINED"
        async with release_session(factory, org) as s:
            assert await record_independent_containment(s, **args) == "CONTAINED"

        async with organization_session(async_sessionmaker(app), org) as s:
            page = await list_case_timeline(s, org_id=org, identity_id=actor, case_id=case_id)
            assert len(page.items) == 1
            assert page.items[0].kind == "INCIDENT_CONTAINMENT_VERIFIED" and page.items[0].revision == 4
            assert page.items[0].evidence_id is None and page.next_cursor is None

        async with admin.connect() as s:
            case = (await s.execute(
                select(InvestigationCase).where(InvestigationCase.id == case_id)
            )).one()
            receipts = (await s.execute(
                select(IncidentContainmentReceipt)
                .where(IncidentContainmentReceipt.case_id == case_id)
            )).all()
            events = (await s.execute(
                select(AuditEntry).where(
                    AuditEntry.org_id == org,
                    AuditEntry.event_type == "INCIDENT_CONTAINMENT_VERIFIED",
                )
            )).all()
            assert case.status == "CONTAINED" and case.revision == 4
            assert len(receipts) == len(events) == 1
            assert receipts[0].gateway_count == 2
            assert receipts[0].archive_sha256 == bytes.fromhex(archived.sha256)
    finally:
        try:
            async with admin.begin() as s:
                for cls in (
                    OutboxEvent, AuditEntry, AuditStream,
                    IncidentContainmentReceipt, CaseMembership,
                    InvestigationCase, ReleaseTarget, ReleaseOrgGuard,
                    Asset, Identity,
                ):
                    await s.execute(delete(cls).where(cls.org_id == org))
                await s.execute(delete(Organization).where(Organization.id == org))
        finally:
            await incident.dispose()
            await app.dispose()
            await admin.dispose()
