"""Native PostgreSQL test for scoped upload-ticket declaration and finalization.

No real S3 or trusted verifier is mocked as successful; fake signer only returns
a staging placeholder. Finalization records UNVERIFIED version claims.
"""
from __future__ import annotations

import asyncio
import json
import os
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import delete, insert, select
from sqlalchemy.ext.asyncio import async_sessionmaker

from aegentra.api import create_app
from aegentra.db import (
    Asset, AuditEntry, AuditStream, BrowserSession, Evidence,
    Identity, IdempotencyRequest, LoginChallenge, Organization,
    OutboxEvent, StagingPart, StagingUpload,
)
from aegentra.oidc import OidcSettings
from aegentra.persistence import make_engine
from aegentra.staging_signer import UploadPut


class FakeProvider:
    async def authenticate(self, code: str, verifier: str, nonce: str) -> str:
        assert code == "ok" and len(verifier) >= 32 and len(nonce) >= 32
        return "submitter-test"


class FakeSigner:
    def issue(self, *, key: str, sha256: str, media_type: str, byte_length: int) -> UploadPut:
        assert key.startswith("staging/")
        assert len(sha256) == 64 and byte_length == 12
        assert media_type == "application/javascript"
        return UploadPut("https://storage.example.test/fixture", {}, 300)


@pytest.mark.skipif(
    not (os.getenv("AEGENTRA_TEST_ADMIN_URL") and os.getenv("AEGENTRA_TEST_APP_URL")),
    reason="native PostgreSQL integration URLs not provided",
)
def test_authenticated_ticket_and_untrusted_finalization() -> None:
    asyncio.run(_exercise())


async def _exercise() -> None:
    admin = make_engine(os.environ["AEGENTRA_TEST_ADMIN_URL"])
    app_engine = make_engine(os.environ["AEGENTRA_TEST_APP_URL"])
    org_id, other_org = uuid4(), uuid4()
    identity_id, asset_id, other_asset = uuid4(), uuid4(), uuid4()
    settings = OidcSettings(
        issuer="https://idp.example.test/",
        authorization_url="https://idp.example.test/authorize",
        token_url="https://idp.example.test/token",
        jwks_url="https://idp.example.test/keys",
        client_id="aegentra-test",
        client_secret="a-reasonably-long-development-test-secret",
        redirect_uri="https://aegentra.test/v1/auth/callback",
        csrf_key=b"d" * 32,
    )
    body = {
        "schema_id": "aegentra.content.v1",
        "parts": [{
            "path": "main.js", "byte_length": 12,
            "sha256": "a" * 64, "media_type": "application/javascript",
        }],
        "edges": [],
    }

    try:
        async with admin.begin() as c:
            await c.execute(insert(Organization), [
                {"id": org_id, "slug": f"ingest-{org_id.hex}"},
                {"id": other_org, "slug": f"ingest-{other_org.hex}"},
            ])
            await c.execute(insert(Identity).values(
                id=identity_id, org_id=org_id, issuer=settings.issuer,
                subject="submitter-test", role="EDITOR", active=True,
                membership_version=1,
            ))
            await c.execute(insert(Asset), [
                {"org_id": org_id, "id": asset_id, "slug": "asset-a", "criticality": "LOW"},
                {"org_id": other_org, "id": other_asset, "slug": "asset-b", "criticality": "LOW"},
            ])

        app = create_app(
            settings=settings,
            sessions=async_sessionmaker(app_engine, expire_on_commit=False),
            provider=FakeProvider(),  # type: ignore[arg-type]
            staging_signer=FakeSigner(),  # type: ignore[arg-type]
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="https://aegentra.test",
            follow_redirects=False,
        ) as client:
            start = await client.get("/v1/auth/login")
            state = parse_qs(urlsplit(start.headers["location"]).query)["state"][0]
            assert (await client.get(
                "/v1/auth/callback", params={"state": state, "code": "ok"}
            )).status_code == 303
            me = (await client.get("/v1/me")).json()
            url = f"/v1/assets/{asset_id}/uploads"
            headers = {
                "Origin": settings.origin,
                "X-CSRF-Token": me["csrf_token"],
                "Idempotency-Key": "upload-test-key-1",
            }
            assert (await client.post(url, json=body)).status_code == 403
            assert (await client.post(
                f"/v1/assets/{other_asset}/uploads", json=body, headers=headers
            )).status_code == 404
            assert (await client.post(
                url, headers=headers,
                content=b'{"schema_id":"x","schema_id":"x"}'
            )).status_code == 422

            issued = await client.post(url, json=body, headers=headers)
            assert issued.status_code == 201, issued.text
            ticket = issued.json()
            assert ticket["status"] == "ISSUED"
            assert ticket["content_sha256"]
            assert len(ticket["signed_parts"]) == 1
            assert ticket["parts"][0]["object_key"].startswith(f"staging/{org_id.hex}/")

            repeat = await client.post(url, json=body, headers=headers)
            assert repeat.status_code == 201
            assert repeat.json()["id"] == ticket["id"]
            changed = {**body, "parts": [{**body["parts"][0], "sha256": "b" * 64}]}
            assert (await client.post(url, json=changed, headers=headers)).status_code == 409

            finalize = f"/v1/uploads/{ticket['id']}/finalize"
            pin = {
                "content_sha256": ticket["content_sha256"],
                "parts": [{"path": "main.js", "version_id": "pinned-123"}],
            }
            assert (await client.post(
                finalize, json={**pin, "parts": []}, headers=headers
            )).status_code == 422
            result = await client.post(finalize, json=pin, headers=headers)
            assert result.status_code == 200, result.text
            assert result.json()["status"] == "AWAITING_VERIFICATION"
            assert (await client.post(finalize, json=pin, headers=headers)).status_code == 200
            assert (await client.post(
                finalize, json={**pin, "parts": [
                    {"path": "main.js", "version_id": "different"}
                ]}, headers=headers,
            )).status_code == 409
            after = await client.post(url, json=body, headers=headers)
            assert after.status_code == 201
            assert after.json()["status"] == "AWAITING_VERIFICATION"
            assert "signed_parts" not in after.json()

        async with admin.connect() as c:
            uploads = (await c.execute(
                select(StagingUpload).where(StagingUpload.org_id == org_id)
            )).all()
            parts = (await c.execute(
                select(StagingPart).where(StagingPart.org_id == org_id)
            )).all()
            events = (await c.execute(
                select(AuditEntry).where(AuditEntry.org_id == org_id)
            )).all()
            outbox = (await c.execute(
                select(OutboxEvent).where(OutboxEvent.org_id == org_id)
            )).all()
            sealed = (await c.execute(
                select(Evidence).where(Evidence.org_id == org_id)
            )).all()
            assert len(uploads) == len(parts) == 1
            assert len(events) == len(outbox) == 2
            assert sealed == []  # No trusted evidence without independent byte check.
    finally:
        try:
            async with admin.begin() as c:
                await c.execute(delete(StagingPart).where(StagingPart.org_id == org_id))
                await c.execute(delete(StagingUpload).where(StagingUpload.org_id == org_id))
                await c.execute(delete(IdempotencyRequest).where(IdempotencyRequest.org_id == org_id))
                await c.execute(delete(OutboxEvent).where(OutboxEvent.org_id == org_id))
                await c.execute(delete(AuditEntry).where(AuditEntry.org_id == org_id))
                await c.execute(delete(AuditStream).where(AuditStream.org_id == org_id))
                await c.execute(delete(BrowserSession).where(BrowserSession.org_id == org_id))
                await c.execute(delete(LoginChallenge))
                await c.execute(delete(Asset).where(Asset.org_id.in_([org_id, other_org])))
                await c.execute(delete(Identity).where(Identity.org_id == org_id))
                await c.execute(delete(Organization).where(
                    Organization.id.in_([org_id, other_org])
                ))
        finally:
            await app_engine.dispose()
            await admin.dispose()
