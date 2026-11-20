"""Native PostgreSQL integration tests.

Run with AEGENTRA_TEST_ADMIN_URL and AEGENTRA_TEST_APP_URL after the Alembic
migration. APP must be a non-owner, NOBYPASSRLS role with scoped table grants.
No Docker or service containers are required.
"""
from __future__ import annotations

import asyncio
import os
from uuid import uuid4

import pytest
from sqlalchemy import delete, insert, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker

from aegentra.asset_store import create_asset, list_assets
from aegentra.db import Asset, Evidence, Organization
from aegentra.persistence import make_engine, organization_session


@pytest.mark.skipif(
    not (os.getenv("AEGENTRA_TEST_ADMIN_URL") and os.getenv("AEGENTRA_TEST_APP_URL")),
    reason="native PostgreSQL integration URLs not provided",
)
def test_real_postgres_rls_and_connection_reset() -> None:
    asyncio.run(_exercise_isolation())


async def _exercise_isolation() -> None:
    admin = make_engine(os.environ["AEGENTRA_TEST_ADMIN_URL"])
    app = make_engine(os.environ["AEGENTRA_TEST_APP_URL"])
    # Force connection reuse: the scope must not leak between transactions.
    from sqlalchemy.ext.asyncio import create_async_engine

    app_one_connection = create_async_engine(
        os.environ["AEGENTRA_TEST_APP_URL"],
        pool_size=1,
        max_overflow=0,
    )

    org_a, org_b = uuid4(), uuid4()
    asset_a, asset_b = uuid4(), uuid4()
    ev_a, ev_b = uuid4(), uuid4()
    name_a, name_b = f"org-{org_a.hex}", f"org-{org_b.hex}"

    try:
        async with admin.begin() as connection:
            for org, name in [(org_a, name_a), (org_b, name_b)]:
                await connection.execute(insert(Organization).values(id=org, slug=name))
            for org, asset in [(org_a, asset_a), (org_b, asset_b)]:
                await connection.execute(
                    insert(Asset).values(org_id=org, id=asset, slug="main", criticality="LOW")
                )
            for org, asset, ev in [(org_a, asset_a, ev_a), (org_b, asset_b, ev_b)]:
                await connection.execute(
                    insert(Evidence).values(
                        org_id=org, id=ev, asset_id=asset, digest=b"z" * 32, kind="fixture"
                    )
                )

        async with admin.connect() as connection:
            flags = (
                await connection.execute(
                    text(
                        "SELECT rolbypassrls, rolsuper FROM pg_roles "
                        "WHERE rolname = 'aegentra_app'"
                    )
                )
            ).one_or_none()
            assert flags == (False, False)
            for table in ("assets", "evidence"):
                scope = (
                    await connection.execute(
                        text(
                            "SELECT relrowsecurity, relforcerowsecurity "
                            "FROM pg_class WHERE oid = to_regclass(:table_name)"
                        ),
                        {"table_name": table},
                    )
                ).one()
                assert scope == (True, True)

        async with app.connect() as connection:
            # No tenant context: RLS must hide all assets and evidence.
            assert (await connection.execute(select(Asset))).all() == []
            assert (await connection.execute(select(Evidence))).all() == []

        factory = async_sessionmaker(app_one_connection, expire_on_commit=False)
        async with organization_session(factory, org_a) as session:
            assets = await list_assets(session, org_id=org_a)
            assert [a.id for a in assets] == [asset_a]
            assert [e.id for e in (await session.scalars(select(Evidence))).all()] == [ev_a]

        async with organization_session(factory, org_b) as session:
            assert [a.id for a in await list_assets(session, org_id=org_b)] == [asset_b]
            assert [e.id for e in (await session.scalars(select(Evidence))).all()] == [ev_b]

        async with factory() as session:
            # The same pool connection now has no organization scope.
            assert (await session.scalars(select(Asset))).all() == []

        with pytest.raises(DBAPIError):
            async with organization_session(factory, org_a) as session:
                # Explicitly bypass repository filtering to confirm RLS itself rejects it.
                await session.execute(
                    insert(Asset).values(
                        org_id=org_b, id=uuid4(), slug="foreign", criticality="LOW"
                    )
                )

        with pytest.raises(DBAPIError):
            async with organization_session(factory, org_a) as session:
                # RLS permits this org, but composite FK rejects an asset from another org.
                await session.execute(
                    insert(Evidence).values(
                        org_id=org_a, id=uuid4(), asset_id=asset_b,
                        digest=b"y" * 32, kind="fixture",
                    )
                )

        async with organization_session(factory, org_a) as session:
            new_asset = await create_asset(
                session, org_id=org_a, slug="added", criticality="MEDIUM"
            )
            inserted_id = new_asset.id
        async with organization_session(factory, org_b) as session:
            assert inserted_id not in [a.id for a in await list_assets(session, org_id=org_b)]
        async with organization_session(factory, org_a) as session:
            assert inserted_id in [a.id for a in await list_assets(session, org_id=org_a)]
    finally:
        try:
            async with admin.begin() as connection:
                await connection.execute(delete(Evidence).where(Evidence.org_id.in_([org_a, org_b])))
                await connection.execute(delete(Asset).where(Asset.org_id.in_([org_a, org_b])))
                await connection.execute(
                    delete(Organization).where(Organization.id.in_([org_a, org_b]))
                )
        finally:
            await app_one_connection.dispose()
            await app.dispose()
            await admin.dispose()
