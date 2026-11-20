"""Native PostgreSQL tests: duplicate messages and stale results are fenced."""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import delete, insert, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker

from aegentra.db import (
    Asset, AuditEntry, AuditStream, Identity, Organization,
    OutboxEvent, ScanJob, StagingPart, StagingUpload,
)
from aegentra.persistence import make_engine, organization_session
from aegentra.scan_leases import acquire_lease, renew_lease, submit_unverified_result


@pytest.mark.skipif(
    not (os.getenv("AEGENTRA_TEST_ADMIN_URL") and os.getenv("AEGENTRA_TEST_APP_URL")),
    reason="native PostgreSQL integration URLs not provided",
)
def test_duplicate_delivery_expiry_and_stale_result_fencing() -> None:
    asyncio.run(_exercise())


async def _exercise() -> None:
    admin = make_engine(os.environ["AEGENTRA_TEST_ADMIN_URL"])
    app = make_engine(os.environ["AEGENTRA_TEST_APP_URL"])
    sessions = async_sessionmaker(app, expire_on_commit=False)
    org, another = uuid4(), uuid4()
    identity, asset, upload, job_id = uuid4(), uuid4(), uuid4(), uuid4()
    now = datetime.now(timezone.utc)
    try:
        async with admin.begin() as c:
            await c.execute(insert(Organization), [
                {"id": org, "slug": f"lease-{org.hex}"},
                {"id": another, "slug": f"lease-{another.hex}"},
            ])
            await c.execute(insert(Identity).values(
                id=identity, org_id=org, issuer="https://test.idp",
                subject="lease-worker", role="EDITOR", active=True,
                membership_version=1,
            ))
            await c.execute(insert(Asset).values(
                org_id=org, id=asset, slug="lease-asset", criticality="LOW",
            ))
            await c.execute(insert(StagingUpload).values(
                org_id=org, id=upload, asset_id=asset,
                issued_by=identity, content_digest=b"a" * 32,
                content_manifest={"schema": "fixture"},
                status="AWAITING_VERIFICATION", created_at=now,
                expires_at=now + timedelta(minutes=15),
            ))
            await c.execute(insert(ScanJob).values(
                org_id=org, id=job_id, upload_id=upload,
                status="QUEUED", created_at=now,
                attempt_generation=0, attempts=0,
            ))

        async with organization_session(sessions, org) as s:
            first = await acquire_lease(
                s, org_id=org, job_id=job_id, actor_id=identity, now=now,
            )
            assert first is not None and first.generation == 1

        async with organization_session(sessions, org) as s:
            assert await acquire_lease(
                s, org_id=org, job_id=job_id, actor_id=identity, now=now,
            ) is None
            assert await renew_lease(
                s, org_id=org, job_id=job_id,
                generation=1, nonce=first.nonce, now=now + timedelta(seconds=15),
            )
            assert not await renew_lease(
                s, org_id=org, job_id=job_id,
                generation=0, nonce=first.nonce, now=now + timedelta(seconds=15),
            )

        expired = now + timedelta(seconds=111)
        async with organization_session(sessions, org) as s:
            second = await acquire_lease(
                s, org_id=org, job_id=job_id, actor_id=identity, now=expired,
            )
            assert second is not None and second.generation == 2
            assert second.nonce != first.nonce
            assert not await submit_unverified_result(
                s, org_id=org, job_id=job_id, actor_id=identity,
                generation=1, nonce=first.nonce, result_sha256=b"x" * 32,
                now=expired,
            )
            assert await submit_unverified_result(
                s, org_id=org, job_id=job_id, actor_id=identity,
                generation=2, nonce=second.nonce, result_sha256=b"y" * 32,
                now=expired,
            )
            assert not await submit_unverified_result(
                s, org_id=org, job_id=job_id, actor_id=identity,
                generation=2, nonce=second.nonce, result_sha256=b"z" * 32,
                now=expired,
            )

        async with organization_session(sessions, another) as s:
            assert await acquire_lease(
                s, org_id=another, job_id=job_id, actor_id=identity, now=now,
            ) is None

        async with admin.connect() as c:
            record = (await c.execute(select(ScanJob).where(ScanJob.id == job_id))).one()
            assert record.status == "PENDING_TRUSTED_VALIDATION"
            assert record.attempt_generation == 2
            assert record.result_sha256 == b"y" * 32
    finally:
        try:
            async with admin.begin() as c:
                await c.execute(delete(OutboxEvent).where(OutboxEvent.org_id == org))
                await c.execute(delete(AuditEntry).where(AuditEntry.org_id == org))
                await c.execute(delete(AuditStream).where(AuditStream.org_id == org))
                await c.execute(delete(ScanJob).where(ScanJob.org_id == org))
                await c.execute(delete(StagingPart).where(StagingPart.org_id == org))
                await c.execute(delete(StagingUpload).where(StagingUpload.org_id == org))
                await c.execute(delete(Asset).where(Asset.org_id == org))
                await c.execute(delete(Identity).where(Identity.org_id == org))
                await c.execute(delete(Organization).where(Organization.id.in_([org, another])))
        finally:
            await app.dispose()
            await admin.dispose()
