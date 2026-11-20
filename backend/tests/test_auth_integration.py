"""Native PostgreSQL end-to-end OIDC session and tenant API integration."""
from __future__ import annotations

import asyncio
import os
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import delete, insert, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker

from aegentra.api import create_app
from aegentra.db import (Asset, AuditEntry, AuditStream, BrowserSession, Identity,
                         IdempotencyRequest, LoginChallenge, Organization, OutboxEvent)
from aegentra.oidc import OidcSettings
from aegentra.persistence import make_engine


class FakeVerifiedProvider:
    """Replaces only network OIDC exchange; crypto verification has separate tests."""

    async def authenticate(self, code: str, verifier: str, nonce: str) -> str:
        assert code == "test-code"
        assert len(verifier) >= 32
        assert len(nonce) >= 32
        return "enrolled-user"


@pytest.mark.skipif(
    not (os.getenv("AEGENTRA_TEST_ADMIN_URL") and os.getenv("AEGENTRA_TEST_APP_URL")),
    reason="native PostgreSQL integration URLs not provided",
)
def test_login_sessions_csrf_and_tenant_assets() -> None:
    asyncio.run(_exercise_auth())


async def _exercise_auth() -> None:
    admin = make_engine(os.environ["AEGENTRA_TEST_ADMIN_URL"])
    app_engine = make_engine(os.environ["AEGENTRA_TEST_APP_URL"])
    org = uuid4()
    other_org = uuid4()
    person = uuid4()
    foreign_asset = uuid4()
    settings = OidcSettings(
        issuer="https://idp.example.test/",
        authorization_url="https://idp.example.test/authorize",
        token_url="https://idp.example.test/token",
        jwks_url="https://idp.example.test/keys",
        client_id="aegentra-test",
        client_secret="a-reasonably-long-development-test-secret",
        redirect_uri="https://aegentra.test/v1/auth/callback",
        csrf_key=b"a" * 32,
    )
    from aegentra.db import Identity

    try:
        async with admin.begin() as session:
            await session.execute(
                insert(Organization),
                [
                    {"id": org, "slug": f"auth-{org.hex}"},
                    {"id": other_org, "slug": f"auth-{other_org.hex}"},
                ],
            )
            await session.execute(
                insert(Identity).values(
                    id=person, org_id=org, issuer=settings.issuer,
                    subject="enrolled-user", role="EDITOR", active=True,
                    membership_version=1,
                )
            )
            await session.execute(
                insert(Asset).values(
                    id=foreign_asset, org_id=other_org, slug="foreign",
                    criticality="HIGH",
                )
            )

        api = create_app(
            settings=settings,
            sessions=async_sessionmaker(app_engine, expire_on_commit=False),
            provider=FakeVerifiedProvider(),  # type: ignore[arg-type]
        )
        transport = httpx.ASGITransport(app=api)
        async with httpx.AsyncClient(
            transport=transport, base_url="https://aegentra.test",
            follow_redirects=False,
        ) as client:
            assert (await client.get("/v1/assets")).status_code == 401
            start = await client.get("/v1/auth/login")
            assert start.status_code == 302
            params = parse_qs(urlsplit(start.headers["location"]).query)
            assert params["code_challenge_method"] == ["S256"]

            done = await client.get(
                "/v1/auth/callback",
                params={"code": "test-code", "state": params["state"][0]},
            )
            assert done.status_code == 303
            assert (await client.get(
                "/v1/auth/callback",
                params={"code": "test-code", "state": params["state"][0]},
            )).status_code == 400

            me = await client.get("/v1/me")
            assert me.status_code == 200
            assert me.json()["role"] == "EDITOR"
            csrf = me.json()["csrf_token"]

            # A same-origin session cookie alone cannot authorize a mutation.
            assert (await client.post(
                "/v1/assets",
                json={"slug": "safe-app", "criticality": "LOW"},
                headers={"Idempotency-Key": "asset-create-0001"},
            )).status_code == 403

            headers = {"Origin": settings.origin, "X-CSRF-Token": csrf,
                       "Idempotency-Key": "asset-create-0001"}
            created = await client.post(
                "/v1/assets",
                json={"slug": "safe-app", "criticality": "LOW"},
                headers=headers,
            )
            assert created.status_code == 201
            assert created.json()["slug"] == "safe-app"
            repeated = await client.post(
                "/v1/assets",
                json={"slug": "safe-app", "criticality": "LOW"},
                headers=headers,
            )
            assert repeated.status_code == 201
            assert repeated.json()["id"] == created.json()["id"]
            assert (await client.post(
                "/v1/assets",
                json={"slug": "different-app", "criticality": "LOW"},
                headers=headers,
            )).status_code == 409
            assert (await client.post(
                "/v1/assets",
                json={"slug": "safe-app", "criticality": "LOW"},
                headers={**headers, "Idempotency-Key": "asset-create-0002"},
            )).status_code == 409
            visible = await client.get("/v1/assets")
            assert visible.status_code == 200
            assert [row["slug"] for row in visible.json()["items"]] == ["safe-app"]

            async with admin.connect() as connection:
                from sqlalchemy import select
                entries = (
                    await connection.execute(
                        select(AuditEntry).where(AuditEntry.org_id == org)
                    )
                ).all()
                outbox = (
                    await connection.execute(
                        select(OutboxEvent).where(OutboxEvent.org_id == org)
                    )
                ).all()
                assert len(entries) == len(outbox) == 1
                assert entries[0].event_type == "ASSET_REGISTERED"
                assert entries[0].previous_hash == bytes(32)

            # A role revocation is read from the database on every request.
            async with admin.begin() as session:
                await session.execute(
                    update(Identity).where(Identity.id == person).values(active=False)
                )
            assert (await client.get("/v1/me")).status_code == 401
            # Re-enabling an identity cannot resurrect the same browser token.
            async with admin.begin() as session:
                await session.execute(
                    update(Identity).where(Identity.id == person).values(active=True)
                )
                current_version = await session.scalar(
                    select(Identity.membership_version).where(Identity.id == person)
                )
                assert current_version == 3
            assert (await client.get("/v1/me")).status_code == 401

            # Only a new verified OIDC transaction gets the new version.
            start = await client.get("/v1/auth/login")
            state = parse_qs(urlsplit(start.headers["location"]).query)["state"][0]
            assert (await client.get(
                "/v1/auth/callback",
                params={"code": "test-code", "state": state},
            )).status_code == 303
            assert (await client.get("/v1/me")).status_code == 200

            # A changed authorization role also invalidates an issued cookie.
            async with admin.begin() as session:
                await session.execute(
                    update(Identity).where(Identity.id == person).values(role="VIEWER")
                )
                current_version = await session.scalar(
                    select(Identity.membership_version).where(Identity.id == person)
                )
                assert current_version == 4
            assert (await client.get("/v1/me")).status_code == 401
    finally:
        try:
            async with admin.begin() as session:
                await session.execute(delete(IdempotencyRequest).where(IdempotencyRequest.org_id == org))
                await session.execute(delete(OutboxEvent).where(OutboxEvent.org_id == org))
                await session.execute(delete(AuditEntry).where(AuditEntry.org_id == org))
                await session.execute(delete(AuditStream).where(AuditStream.org_id == org))
                await session.execute(delete(BrowserSession).where(BrowserSession.org_id == org))
                await session.execute(delete(LoginChallenge))
                await session.execute(delete(Asset).where(Asset.org_id.in_([org, other_org])))
                await session.execute(delete(Identity).where(Identity.id == person))
                await session.execute(
                    delete(Organization).where(Organization.id.in_([org, other_org]))
                )
        finally:
            await app_engine.dispose()
            await admin.dispose()
