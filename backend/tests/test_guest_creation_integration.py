"""PostgreSQL native bridge role: intents are durable, fenced, RLS-scoped."""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker

from aegentra.bridge_journal import reserve_attempt
from aegentra.guest_physical_operations import (
    PhysicalConflict, mark_operation_unknown, prepare_operation, record_operation,
)
from aegentra.db import (
    Asset, AuditEntry, AuditStream, GuestAttempt, GuestCreateIntent,
    GuestPhysicalOperation, GuestResource, Identity, Organization,
    OutboxEvent, ScanJob, StagingUpload,
)
from aegentra.guest_creation import (
    CreationConflict, prepare_creation, quarantine_creation, record_creation,
)
from aegentra.persistence import make_engine, organization_session


@pytest.mark.skipif(
    not all(os.getenv(x) for x in (
        "AEGENTRA_TEST_ADMIN_URL", "AEGENTRA_TEST_APP_URL",
        "AEGENTRA_TEST_BRIDGE_URL",
    )),
    reason="isolated native PostgreSQL bridge roles not configured",
)
def test_aws_creation_intents_require_order_and_retain_unknown() -> None:
    asyncio.run(exercise())


async def exercise() -> None:
    admin = make_engine(os.environ["AEGENTRA_TEST_ADMIN_URL"])
    app = make_engine(os.environ["AEGENTRA_TEST_APP_URL"])
    bridge = make_engine(os.environ["AEGENTRA_TEST_BRIDGE_URL"])
    sessions = async_sessionmaker(bridge, expire_on_commit=False)
    org, other, actor, asset = (uuid4() for _ in range(4))
    uploads = [uuid4() for _ in range(4)]
    jobs = [uuid4() for _ in range(4)]
    now = datetime.now(timezone.utc)
    nonce = "n" * 43
    plan_sha256 = "a" * 64
    client_tokens = ("b" * 64, "c" * 64, "d" * 64)
    reservation = dict(
        org_id=org, actor_id=actor, generation=1,
        nonce=nonce, input_sha256=b"i" * 32,
        toolchain_sha256=b"t" * 32,
        ami_id="ami-00000000000000001",
        account_id="123456789012", availability_zone="us-east-1a",
        subnet_id="subnet-test", security_group_id="sg-test",
        kms_key_arn="arn:aws:kms:us-east-1:123456789012:key/test", now=now,
    )

    async def prepare(job: int, kind: str, token: str, moment: datetime) -> None:
        async with organization_session(sessions, org) as s:
            await prepare_creation(
                s, org_id=org, job_id=jobs[job], actor_id=actor,
                generation=1, kind=kind, plan_sha256=plan_sha256,
                client_token=token, now=moment,
            )

    async def record(job: int, kind: str, token: str, resource: str,
                     moment: datetime) -> str:
        async with organization_session(sessions, org) as s:
            return await record_creation(
                s, org_id=org, job_id=jobs[job], actor_id=actor,
                generation=1, kind=kind, plan_sha256=plan_sha256,
                client_token=token, resource_id=resource, now=moment,
            )

    try:
        async with admin.begin() as s:
            await s.execute(insert(Organization), [
                {"id": org, "slug": f"creation-{org.hex}"},
                {"id": other, "slug": f"creation-{other.hex}"},
            ])
            await s.execute(insert(Identity).values(
                id=actor, org_id=org, issuer="https://idp.test",
                subject="guest-creation", role="EDITOR", active=True,
                membership_version=1,
            ))
            await s.execute(insert(Asset).values(
                org_id=org, id=asset, slug="guest", criticality="LOW",
            ))
            await s.execute(insert(StagingUpload), [
                {
                    "org_id": org, "id": upload, "asset_id": asset,
                    "issued_by": actor, "content_digest": b"i" * 32,
                    "content_manifest": {}, "status": "AWAITING_VERIFICATION",
                    "created_at": now, "expires_at": now + timedelta(minutes=15),
                }
                for upload in uploads
            ])
            await s.execute(insert(ScanJob), [
                {
                    "org_id": org, "id": job, "upload_id": upload,
                    "status": "LEASED", "created_at": now,
                    "attempts": 1, "attempt_generation": 1,
                    "lease_nonce": nonce,
                    "lease_expires": now + timedelta(seconds=90),
                    "attempt_deadline": now + timedelta(minutes=8),
                }
                for job, upload in zip(jobs, uploads)
            ])
        for job in jobs:
            async with organization_session(sessions, org) as s:
                await reserve_attempt(s, job_id=job, **reservation)

        await prepare(0, "INPUT_EBS", client_tokens[0], now)
        with pytest.raises(CreationConflict, match="unresolved"):
            await prepare(0, "INPUT_EBS", client_tokens[0], now)
        with pytest.raises(CreationConflict, match="unresolved"):
            await prepare(0, "OUTPUT_EBS", client_tokens[1], now)
        assert await record(
            0, "INPUT_EBS", client_tokens[0],
            "vol-00000000000000001", now,
        ) == "RECORDED"
        await prepare(0, "OUTPUT_EBS", client_tokens[1], now)
        assert await record(
            0, "OUTPUT_EBS", client_tokens[1],
            "vol-00000000000000002", now,
        ) == "RECORDED"
        await prepare(0, "INSTANCE", client_tokens[2], now)
        assert await record(
            0, "INSTANCE", client_tokens[2],
            "i-00000000000000001", now,
        ) == "RECORDED"
        with pytest.raises(CreationConflict):
            await record(
                0, "INPUT_EBS", client_tokens[0],
                "vol-00000000000000009", now,
            )
        async with organization_session(sessions, org) as s:
            intent = await s.scalar(select(GuestCreateIntent).where(
                GuestCreateIntent.org_id == org,
                GuestCreateIntent.job_id == jobs[0],
                GuestCreateIntent.kind == "INPUT_EBS",
            ))
            assert intent is not None
            assert intent.status == "RECORDED"
            assert intent.resource_id == "vol-00000000000000001"
            statuses = (await s.scalars(select(GuestAttempt.state).where(
                GuestAttempt.org_id == org, GuestAttempt.job_id == jobs[0],
            ))).all()
            assert statuses == ["INSTANCE_RECORDED"]
            assert len((await s.scalars(select(GuestResource).where(
                GuestResource.org_id == org, GuestResource.job_id == jobs[0],
            ))).all()) == 3

        # Exact raw attachments are globally journaled and strictly ordered.
        async with organization_session(sessions, org) as s:
            with pytest.raises(PhysicalConflict, match="order"):
                await prepare_operation(
                    s, org_id=org, job_id=jobs[0], generation=1,
                    actor_id=actor, kind="ATTACH_OUTPUT", now=now,
                )
            exact = await prepare_operation(
                s, org_id=org, job_id=jobs[0], generation=1,
                actor_id=actor, kind="ATTACH_INPUT", now=now,
            )
        async with organization_session(sessions, org) as s:
            with pytest.raises(PhysicalConflict, match="already"):
                await prepare_operation(
                    s, org_id=org, job_id=jobs[0], generation=1,
                    actor_id=actor, kind="ATTACH_INPUT", now=now,
                )
            assert await record_operation(
                s, org_id=org, job_id=jobs[0], generation=1,
                actor_id=actor, kind="ATTACH_INPUT", expected=exact, now=now,
            ) == "VERIFIED"
        async with organization_session(sessions, org) as s:
            assert await prepare_operation(
                s, org_id=org, job_id=jobs[0], generation=1,
                actor_id=actor, kind="ATTACH_OUTPUT", now=now,
            ) == exact
        async with organization_session(sessions, org) as s:
            assert await record_operation(
                s, org_id=org, job_id=jobs[0], generation=1,
                actor_id=actor, kind="ATTACH_OUTPUT", expected=exact, now=now,
            ) == "VERIFIED"
        async with organization_session(sessions, org) as s:
            await prepare_operation(
                s, org_id=org, job_id=jobs[0], generation=1,
                actor_id=actor, kind="TERMINATE", now=now,
            )
        async with organization_session(sessions, org) as s:
            assert await record_operation(
                s, org_id=org, job_id=jobs[0], generation=1,
                actor_id=actor, kind="TERMINATE", expected=exact, now=now,
            ) == "REQUESTED"
            # AWS request acceptance is never evidence of termination.
            assert (await s.scalar(select(GuestAttempt.state).where(
                GuestAttempt.org_id == org, GuestAttempt.job_id == jobs[0],
            ))) == "INSTANCE_RECORDED"
        with pytest.raises(DBAPIError, match="outcome is terminal"):
            async with organization_session(sessions, org) as s:
                await s.execute(update(GuestPhysicalOperation).where(
                    GuestPhysicalOperation.org_id == org,
                    GuestPhysicalOperation.job_id == jobs[0],
                    GuestPhysicalOperation.kind == "ATTACH_INPUT",
                ).values(state="UNKNOWN"))

        # A failed attachment permanently quarantines its physical attempt.
        for kind, token, resource in (
            ("INPUT_EBS", "1" * 64, "vol-00000000000000005"),
            ("OUTPUT_EBS", "2" * 64, "vol-00000000000000006"),
            ("INSTANCE", "3" * 64, "i-00000000000000004"),
        ):
            await prepare(3, kind, token, now)
            assert await record(3, kind, token, resource, now) == "RECORDED"
        async with organization_session(sessions, org) as s:
            await prepare_operation(
                s, org_id=org, job_id=jobs[3], generation=1,
                actor_id=actor, kind="ATTACH_INPUT", now=now,
            )
        async with organization_session(sessions, org) as s:
            await mark_operation_unknown(
                s, org_id=org, job_id=jobs[3], generation=1,
                actor_id=actor, kind="ATTACH_INPUT", now=now,
            )
            assert (await s.scalar(select(GuestAttempt.state).where(
                GuestAttempt.org_id == org, GuestAttempt.job_id == jobs[3],
            ))) == "QUARANTINED"
            with pytest.raises(PhysicalConflict):
                await prepare_operation(
                    s, org_id=org, job_id=jobs[3], generation=1,
                    actor_id=actor, kind="ATTACH_OUTPUT", now=now,
                )
        # A separately governed stop may still target the exact recorded
        # instance after a failed attach, but cannot claim it is detached.
        async with organization_session(sessions, org) as s:
            quarantined = await prepare_operation(
                s, org_id=org, job_id=jobs[3], generation=1,
                actor_id=actor, kind="TERMINATE", now=now,
            )
            assert quarantined.instance_id == "i-00000000000000004"
        async with organization_session(sessions, org) as s:
            assert await record_operation(
                s, org_id=org, job_id=jobs[3], generation=1,
                actor_id=actor, kind="TERMINATE", expected=quarantined, now=now,
            ) == "REQUESTED"

        # All intent identity fields are immutable, even for the bridge role.
        with pytest.raises(DBAPIError, match="creation intent immutable"):
            async with organization_session(sessions, org) as s:
                await s.execute(update(GuestCreateIntent).where(
                    GuestCreateIntent.org_id == org,
                    GuestCreateIntent.job_id == jobs[0],
                    GuestCreateIntent.kind == "INPUT_EBS",
                ).values(plan_sha256=b"x" * 32))
        with pytest.raises(DBAPIError, match="outcome cannot be rewritten"):
            async with organization_session(sessions, org) as s:
                await s.execute(update(GuestCreateIntent).where(
                    GuestCreateIntent.org_id == org,
                    GuestCreateIntent.job_id == jobs[0],
                    GuestCreateIntent.kind == "INPUT_EBS",
                ).values(status="UNKNOWN", resource_id=None))

        await prepare(1, "INPUT_EBS", "e" * 64, now)
        async with organization_session(sessions, org) as s:
            await quarantine_creation(
                s, org_id=org, job_id=jobs[1], generation=1,
                actor_id=actor, kind="INPUT_EBS", now=now,
            )
        with pytest.raises(CreationConflict):
            await prepare(1, "OUTPUT_EBS", "f" * 64, now)
        with pytest.raises(CreationConflict):
            await record(1, "INPUT_EBS", "e" * 64,
                         "vol-00000000000000003", now)
        async with organization_session(sessions, org) as s:
            assert (await s.scalar(select(GuestAttempt.state).where(
                GuestAttempt.org_id == org, GuestAttempt.job_id == jobs[1],
            ))) == "QUARANTINED"
            assert (await s.scalar(select(GuestCreateIntent.status).where(
                GuestCreateIntent.org_id == org, GuestCreateIntent.job_id == jobs[1],
            ))) == "UNKNOWN"

        # Late return after lease generation advance is still journaled for
        # janitor reconciliation but never marked as eligible for guest use.
        await prepare(2, "INPUT_EBS", "f" * 64, now)
        async with admin.begin() as s:
            await s.execute(update(ScanJob).where(
                ScanJob.org_id == org, ScanJob.id == jobs[2],
            ).values(attempt_generation=2, lease_nonce="z" * 43))
        assert await record(
            2, "INPUT_EBS", "f" * 64,
            "vol-00000000000000004", now,
        ) == "RECORDED_QUARANTINED"
        async with organization_session(sessions, org) as s:
            assert (await s.scalar(select(GuestAttempt.state).where(
                GuestAttempt.org_id == org, GuestAttempt.job_id == jobs[2],
            ))) == "QUARANTINED"
            assert (await s.scalar(select(GuestResource.resource_id).where(
                GuestResource.org_id == org, GuestResource.job_id == jobs[2],
            ))) == "vol-00000000000000004"

        # RLS protects creation intents and API credentials have no table grant.
        async with organization_session(sessions, other) as s:
            assert (await s.scalars(select(GuestCreateIntent))).all() == []
            assert (await s.scalars(select(GuestPhysicalOperation))).all() == []
        with pytest.raises(DBAPIError, match="permission denied"):
            app_sessions = async_sessionmaker(app)
            async with organization_session(app_sessions, org) as s:
                await s.execute(select(GuestCreateIntent))
        with pytest.raises(DBAPIError, match="permission denied"):
            async with organization_session(app_sessions, org) as s:
                await s.execute(select(GuestPhysicalOperation))
    finally:
        try:
            async with admin.begin() as s:
                for model in (
                    OutboxEvent, AuditEntry, AuditStream,
                    GuestPhysicalOperation, GuestCreateIntent,
                    GuestResource, GuestAttempt,
                    ScanJob, StagingUpload, Asset, Identity,
                ):
                    await s.execute(delete(model).where(model.org_id == org))
                await s.execute(delete(Organization).where(
                    Organization.id.in_([org, other]),
                ))
        finally:
            await bridge.dispose()
            await app.dispose()
            await admin.dispose()
