"""Native PostgreSQL outbox retry/fencing and stream-order integration."""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker

from aegentra.audit import record_event
from aegentra.db import (
    Asset, AuditEntry, AuditStream, Identity, Organization, OutboxEvent,
)
from aegentra.outbox_dispatch import (
    DispatchRejected, acknowledge_delivery, claim_outbox, fail_delivery,
)
from aegentra.persistence import make_engine, organization_session


@pytest.mark.skipif(
    not all(os.getenv(key) for key in (
        "AEGENTRA_TEST_ADMIN_URL", "AEGENTRA_TEST_APP_URL",
        "AEGENTRA_TEST_OUTBOX_URL",
    )),
    reason="native PostgreSQL dispatcher role not configured",
)
def test_at_least_once_delivery_with_generation_fencing() -> None:
    asyncio.run(_exercise())


async def _exercise() -> None:
    admin = make_engine(os.environ["AEGENTRA_TEST_ADMIN_URL"])
    app = make_engine(os.environ["AEGENTRA_TEST_APP_URL"])
    worker = make_engine(os.environ["AEGENTRA_TEST_OUTBOX_URL"])
    factory = async_sessionmaker(worker, expire_on_commit=False)
    org, other, actor, asset = (uuid4() for _ in range(4))
    now = datetime.now(timezone.utc)
    try:
        async with admin.begin() as s:
            await s.execute(insert(Organization), [
                {"id": org, "slug": f"dispatch-{org.hex}"},
                {"id": other, "slug": f"dispatch-{other.hex}"},
            ])
            await s.execute(insert(Identity).values(
                id=actor, org_id=org, issuer="https://idp.example.test",
                subject="outbox-owner", role="ADMIN",
                active=True, membership_version=1,
            ))
            await s.execute(insert(Asset).values(
                org_id=org, id=asset, slug="dispatch-asset", criticality="LOW",
            ))
        admin_factory = async_sessionmaker(admin, expire_on_commit=False)
        async with organization_session(admin_factory, org) as s:
            await record_event(
                s, org_id=org, actor_id=actor, stream="dispatch",
                event_type="FIRST_EVENT", body={"safe": True},
            )
            await record_event(
                s, org_id=org, actor_id=actor, stream="dispatch",
                event_type="SECOND_EVENT", body={"safe": False},
            )

        async with organization_session(factory, other) as s:
            assert await claim_outbox(s, org_id=other, now=now) == ()

        async with organization_session(factory, org) as s:
            first = await claim_outbox(s, org_id=org, now=now)
            assert len(first) == 1 and first[0].sequence == 1
            assert len(first[0].audit_hash) == 64
            assert first[0].event_type == "FIRST_EVENT"
            assert first[0].attempt == first[0].generation == 1

        # The predecessor is still in flight, so later stream seq cannot jump.
        async with organization_session(factory, org) as s:
            assert await claim_outbox(s, org_id=org, now=now) == ()
            with pytest.raises(DispatchRejected):
                await fail_delivery(
                    s, org_id=org, event_id=first[0].event_id,
                    generation=first[0].generation, nonce=first[0].nonce,
                    code="RAW_SECRET_DATA", now=now,
                )
            assert await fail_delivery(
                s, org_id=org, event_id=first[0].event_id,
                generation=first[0].generation, nonce=first[0].nonce,
                code="DEPENDENCY_UNAVAILABLE", now=now,
            ) == "RETRY_SCHEDULED"

        async with organization_session(factory, org) as s:
            assert not await acknowledge_delivery(
                s, org_id=org, event_id=first[0].event_id,
                generation=first[0].generation, nonce=first[0].nonce,
                delivery_reference="sink-receipt-1", now=now,
            )
            assert await claim_outbox(
                s, org_id=org, now=now + timedelta(seconds=1),
            ) == ()
            retried = await claim_outbox(
                s, org_id=org, now=now + timedelta(seconds=3),
            )
            assert len(retried) == 1 and retried[0].sequence == 1
            assert retried[0].generation == 2
            assert retried[0].nonce != first[0].nonce

        async with organization_session(factory, org) as s:
            assert await acknowledge_delivery(
                s, org_id=org, event_id=retried[0].event_id,
                generation=retried[0].generation, nonce=retried[0].nonce,
                delivery_reference="sink-receipt-1",
                now=now + timedelta(seconds=4),
            )
        async with organization_session(factory, org) as s:
            assert await acknowledge_delivery(
                s, org_id=org, event_id=retried[0].event_id,
                generation=retried[0].generation, nonce=retried[0].nonce,
                delivery_reference="sink-receipt-1",
                now=now + timedelta(seconds=5),
            )
            remaining = await claim_outbox(
                s, org_id=org, now=now + timedelta(seconds=6),
            )
            assert len(remaining) == 1 and remaining[0].sequence == 2

        with pytest.raises(DBAPIError, match="permission denied"):
            async with organization_session(
                async_sessionmaker(app), org
            ) as s:
                await s.execute(
                    update(OutboxEvent)
                    .where(OutboxEvent.org_id == org)
                    .values(delivered_at=now)
                )

        async with admin.connect() as s:
            rows = (await s.execute(
                select(OutboxEvent).where(
                    OutboxEvent.org_id == org,
                ).order_by(OutboxEvent.sequence)
            )).all()
            assert len(rows) == 2
            assert rows[0].delivered_at is not None
            assert rows[0].lease_generation == 2
            assert rows[1].delivered_at is None
    finally:
        try:
            async with admin.begin() as s:
                await s.execute(delete(OutboxEvent).where(
                    OutboxEvent.org_id == org,
                ))
                await s.execute(delete(AuditEntry).where(
                    AuditEntry.org_id == org,
                ))
                await s.execute(delete(AuditStream).where(
                    AuditStream.org_id == org,
                ))
                await s.execute(delete(Asset).where(Asset.org_id == org))
                await s.execute(delete(Identity).where(Identity.org_id == org))
                await s.execute(delete(Organization).where(
                    Organization.id.in_([org, other])
                ))
        finally:
            await worker.dispose()
            await app.dispose()
            await admin.dispose()
