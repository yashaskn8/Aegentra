"""Native PostgreSQL tests for case authorization and evidence scope."""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

import httpx
import pytest
from hypothesis import example, given, settings, strategies as st
from sqlalchemy import delete, insert, update
from sqlalchemy.ext.asyncio import async_sessionmaker

from aegentra.api import create_app
from aegentra.db import (
    Asset, AuditEntry, AuditStream, BrowserSession, CaseEvidence, CaseMembership,
    Evidence, Identity, IdempotencyRequest, InvestigationCase, LoginChallenge,
    Organization, OutboxEvent, ScanJob, StagingUpload,
)
from aegentra.oidc import OidcSettings
from aegentra.persistence import make_engine


class FakeProvider:
    async def authenticate(self, code: str, verifier: str, nonce: str) -> str:
        assert len(verifier) >= 32
        assert len(nonce) >= 32
        if code not in {"analyst", "viewer"}:
            raise ValueError("unexpected test user")
        return f"{code}-subject"


async def sign_in(client: httpx.AsyncClient, code: str) -> dict:
    start = await client.get("/v1/auth/login")
    assert start.status_code == 302
    state = parse_qs(urlsplit(start.headers["location"]).query)["state"][0]
    callback = await client.get(
        "/v1/auth/callback", params={"code": code, "state": state}
    )
    assert callback.status_code == 303
    me = await client.get("/v1/me")
    assert me.status_code == 200
    return me.json()


@pytest.mark.skipif(
    not (os.getenv("AEGENTRA_TEST_ADMIN_URL") and os.getenv("AEGENTRA_TEST_APP_URL")),
    reason="native PostgreSQL integration URLs not provided",
)
@settings(max_examples=3, derandomize=True, deadline=None)
@given(stale_revision=st.sampled_from([3, 4, 100]))
@example(stale_revision=1)
def test_cases_are_membership_scoped_and_evidence_is_asset_bound(stale_revision: int) -> None:
    asyncio.run(exercise_case_scope(stale_revision))


async def exercise_case_scope(stale_revision: int) -> None:
    admin = make_engine(os.environ["AEGENTRA_TEST_ADMIN_URL"])
    app_engine = make_engine(os.environ["AEGENTRA_TEST_APP_URL"])
    org, other_org = uuid4(), uuid4()
    analyst, viewer = uuid4(), uuid4()
    asset_a, asset_b, foreign_asset = uuid4(), uuid4(), uuid4()
    ev_a, ev_b, foreign_ev, ev_after_triage = (uuid4() for _ in range(4))
    upload_id, scan_id = uuid4(), uuid4()
    settings = OidcSettings(
        issuer="https://idp.example.test/",
        authorization_url="https://idp.example.test/authorize",
        token_url="https://idp.example.test/token",
        jwks_url="https://idp.example.test/keys",
        client_id="aegentra-test",
        client_secret="a-reasonably-long-development-test-secret",
        redirect_uri="https://aegentra.test/v1/auth/callback",
        csrf_key=b"c" * 32,
    )

    try:
        async with admin.begin() as session:
            await session.execute(insert(Organization), [
                {"id": org, "slug": f"case-{org.hex}"},
                {"id": other_org, "slug": f"case-{other_org.hex}"},
            ])
            await session.execute(insert(Identity), [
                {
                    "id": analyst, "org_id": org, "issuer": settings.issuer,
                    "subject": "analyst-subject", "role": "ANALYST",
                    "active": True, "membership_version": 1,
                },
                {
                    "id": viewer, "org_id": org, "issuer": settings.issuer,
                    "subject": "viewer-subject", "role": "VIEWER",
                    "active": True, "membership_version": 1,
                },
            ])
            await session.execute(insert(Asset), [
                {"id": asset_a, "org_id": org, "slug": "asset-a", "criticality": "LOW"},
                {"id": asset_b, "org_id": org, "slug": "asset-b", "criticality": "LOW"},
                {"id": foreign_asset, "org_id": other_org, "slug": "asset-c", "criticality": "LOW"},
            ])
            now = datetime.now(timezone.utc)
            await session.execute(insert(StagingUpload).values(
                org_id=org, id=upload_id, asset_id=asset_a, issued_by=analyst,
                content_digest=b"a" * 32, content_manifest={"schema": "synthetic"},
                status="ISSUED", created_at=now, expires_at=now + timedelta(minutes=15),
            ))
            await session.execute(insert(ScanJob).values(
                org_id=org, id=scan_id, upload_id=upload_id,
                status="QUEUED", created_at=now, attempt_generation=0, attempts=0,
            ))
            await session.execute(insert(Evidence), [
                {
                    "id": ev_a, "org_id": org, "asset_id": asset_a,
                    "digest": b"a" * 32, "kind": "synthetic",
                },
                {
                    "id": ev_b, "org_id": org, "asset_id": asset_b,
                    "digest": b"b" * 32, "kind": "synthetic",
                },
                {
                    "id": foreign_ev, "org_id": other_org, "asset_id": foreign_asset,
                    "digest": b"c" * 32, "kind": "synthetic",
                },
                {
                    "id": ev_after_triage, "org_id": org, "asset_id": asset_a,
                    "digest": b"d" * 32, "kind": "synthetic",
                },
            ])

        api = create_app(
            settings=settings,
            sessions=async_sessionmaker(app_engine, expire_on_commit=False),
            provider=FakeProvider(),  # type: ignore[arg-type]
        )
        transport = httpx.ASGITransport(app=api)
        async with httpx.AsyncClient(
            transport=transport, base_url="https://aegentra.test",
            follow_redirects=False,
        ) as analyst_client:
            me = await sign_in(analyst_client, "analyst")
            headers = {
                "Origin": settings.origin,
                "X-CSRF-Token": me["csrf_token"],
                "Idempotency-Key": "case-create-0001",
            }
            payload = {"asset_id": str(asset_a), "title": "Synthetic review"}
            assert (await analyst_client.post(
                "/v1/cases", json=payload,
                headers={"Idempotency-Key": "case-create-0001"},
            )).status_code == 403
            created = await analyst_client.post("/v1/cases", json=payload, headers=headers)
            assert created.status_code == 201, created.text
            case_id = created.json()["id"]
            repeated = await analyst_client.post("/v1/cases", json=payload, headers=headers)
            assert repeated.status_code == 201
            assert repeated.json()["id"] == case_id
            conflict = await analyst_client.post(
                "/v1/cases",
                json={**payload, "title": "Changed title"}, headers=headers,
            )
            assert conflict.status_code == 409
            cases = await analyst_client.get("/v1/cases")
            assert cases.status_code == 200
            assert [case["id"] for case in cases.json()["items"]] == [case_id]

            status_response = await analyst_client.get("/v1/operations/scans")
            assert status_response.status_code == 200
            assert status_response.headers["cache-control"] == "no-store"
            assert status_response.json() == {
                "items": [{
                    "id": str(scan_id), "asset_id": str(asset_a),
                    "status": "QUEUED", "attempts": 0,
                    "created_at": now.isoformat(),
                }],
                "truncated": False,
            }

            wrong_asset = await analyst_client.post(
                f"/v1/cases/{case_id}/evidence",
                json={"evidence_id": str(ev_b)}, headers=headers,
            )
            assert wrong_asset.status_code == 404
            wrong_org = await analyst_client.post(
                f"/v1/cases/{case_id}/evidence",
                json={"evidence_id": str(foreign_ev)}, headers=headers,
            )
            assert wrong_org.status_code == 404
            unlinked = await analyst_client.get(
                f"/v1/cases/{case_id}/evidence/{ev_a}/meta"
            )
            assert unlinked.status_code == 404
            linked = await analyst_client.post(
                f"/v1/cases/{case_id}/evidence",
                json={"evidence_id": str(ev_a)}, headers=headers,
            )
            assert linked.status_code == 201
            metadata = await analyst_client.get(
                f"/v1/cases/{case_id}/evidence/{ev_a}/meta"
            )
            assert metadata.status_code == 200
            assert metadata.json()["sha256"] == (b"a" * 32).hex()

            first_page = await analyst_client.get(
                f"/v1/cases/{case_id}/evidence", params={"page_size": 1}
            )
            assert first_page.status_code == 200, first_page.text
            assert [item["id"] for item in first_page.json()["items"]] == [str(ev_a)]
            assert first_page.json()["next_cursor"] is None
            assert (await analyst_client.get(
                f"/v1/cases/{case_id}/evidence",
                params={"cursor": "@@"},
            )).status_code == 422

            response = await analyst_client.post(
                f"/v1/cases/{case_id}/transition",
                json={"status": "TRIAGED", "expected_revision": 1},
                headers=headers,
            )
            assert response.status_code == 200, response.text
            assert response.json()["enforcement_effect"] == "NONE"
            assert response.json()["revision"] == 2
            stale = await analyst_client.post(
                f"/v1/cases/{case_id}/transition",
                json={"status": "CONTAINMENT_REQUESTED", "expected_revision": stale_revision},
                headers=headers,
            )
            assert stale.status_code == 409
            response = await analyst_client.post(
                f"/v1/cases/{case_id}/transition",
                json={"status": "CONTAINMENT_REQUESTED", "expected_revision": 2},
                headers=headers,
            )
            assert response.status_code == 200, response.text
            assert response.json()["status"] == "CONTAINMENT_REQUESTED"
            assert response.json()["revision"] == 3
            added_after_triage = await analyst_client.post(
                f"/v1/cases/{case_id}/evidence",
                json={"evidence_id": str(ev_after_triage)}, headers=headers,
            )
            assert added_after_triage.status_code == 201, added_after_triage.text
            assert (await analyst_client.get(
                f"/v1/cases/{case_id}/evidence/{ev_after_triage}/meta"
            )).status_code == 200

            tied_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
            async with admin.begin() as conn:
                await conn.execute(
                    update(CaseEvidence).where(CaseEvidence.org_id == org, CaseEvidence.case_id == UUID(case_id))
                    .values(linked_at=tied_at)
                )
            first_page = await analyst_client.get(
                f"/v1/cases/{case_id}/evidence", params={"page_size": 1}
            )
            assert first_page.status_code == 200
            assert len(first_page.json()["items"]) == 1
            assert first_page.json()["next_cursor"]
            second_page = await analyst_client.get(
                f"/v1/cases/{case_id}/evidence",
                params={"page_size": 1, "cursor": first_page.json()["next_cursor"]},
            )
            assert second_page.status_code == 200, second_page.text
            assert second_page.json()["next_cursor"] is None
            pages = first_page.json()["items"] + second_page.json()["items"]
            assert [item["id"] for item in pages] == [str(i) for i in sorted((ev_a, ev_after_triage))]
            assert [datetime.fromisoformat(item["linked_at"]) for item in pages] == [tied_at, tied_at]
            assert (await analyst_client.get(
                f"/v1/cases/{case_id}/evidence",
                params={"cursor": first_page.json()["next_cursor"] + "garbage"},
            )).status_code == 422
            invalid = await analyst_client.post(
                f"/v1/cases/{case_id}/transition",
                json={"status": "CONTAINED", "expected_revision": 3},
                headers=headers,
            )
            assert invalid.status_code == 422

            async with httpx.AsyncClient(
                transport=transport, base_url="https://aegentra.test",
                follow_redirects=False,
            ) as viewer_client:
                viewer_me = await sign_in(viewer_client, "viewer")
                assert (await viewer_client.get("/v1/cases")).json()["items"] == []
                assert (await viewer_client.get("/v1/operations/scans")).status_code == 403
                assert (await viewer_client.get(f"/v1/cases/{case_id}")).status_code == 404
                assert (await viewer_client.get(
                    f"/v1/cases/{case_id}/evidence"
                )).status_code == 404
                assert (await viewer_client.get(
                    f"/v1/cases/{case_id}/evidence/{ev_a}/meta"
                )).status_code == 404
                viewer_headers = {
                    "Origin": settings.origin,
                    "X-CSRF-Token": viewer_me["csrf_token"],
                    "Idempotency-Key": "viewer-create-0001",
                }
                assert (await viewer_client.post(
                    "/v1/cases", json=payload, headers=viewer_headers,
                )).status_code == 403
                assert (await viewer_client.post(
                    f"/v1/cases/{case_id}/evidence",
                    json={"evidence_id": str(ev_a)}, headers=viewer_headers,
                )).status_code == 403
    finally:
        try:
            async with admin.begin() as session:
                await session.execute(delete(CaseEvidence).where(CaseEvidence.org_id == org))
                await session.execute(delete(CaseMembership).where(CaseMembership.org_id == org))
                await session.execute(delete(InvestigationCase).where(InvestigationCase.org_id == org))
                await session.execute(delete(IdempotencyRequest).where(IdempotencyRequest.org_id == org))
                await session.execute(delete(OutboxEvent).where(OutboxEvent.org_id == org))
                await session.execute(delete(AuditEntry).where(AuditEntry.org_id == org))
                await session.execute(delete(AuditStream).where(AuditStream.org_id == org))
                await session.execute(delete(BrowserSession).where(BrowserSession.org_id == org))
                await session.execute(delete(LoginChallenge))
                await session.execute(delete(ScanJob).where(ScanJob.org_id == org))
                await session.execute(delete(StagingUpload).where(StagingUpload.org_id == org))
                await session.execute(delete(Evidence).where(Evidence.org_id.in_([org, other_org])))
                await session.execute(delete(Asset).where(Asset.org_id.in_([org, other_org])))
                await session.execute(delete(Identity).where(Identity.org_id == org))
                await session.execute(delete(Organization).where(Organization.id.in_([org, other_org])))
        finally:
            await app_engine.dispose()
            await admin.dispose()
