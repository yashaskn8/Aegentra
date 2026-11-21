"""Native PostgreSQL custody journal: independent bridge role, fencing, RLS."""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker

from aegentra.bridge_custody import CustodyError, DetachedInventory
from aegentra.bridge_journal import (
    BridgeConflict, record_instance, record_volumes, reserve_attempt,
    record_verified_detach,
)
from aegentra.bridge_disposal import (
    DeletedInventory, DisposalRejected, begin_guest_disposal,
    record_verified_disposal,
)
from aegentra.db import (
    Asset, AuditEntry, AuditStream, GuestAttempt, GuestResource, Identity,
    Organization, OutboxEvent, ScanJob, ScanReceipt, StagingUpload,
)
from aegentra.persistence import make_engine, organization_session


@pytest.mark.skipif(
    not all(os.getenv(name) for name in (
        "AEGENTRA_TEST_ADMIN_URL", "AEGENTRA_TEST_APP_URL", "AEGENTRA_TEST_BRIDGE_URL"
    )),
    reason="native bridge and PostgreSQL roles not provided",
)
def test_bridge_is_fenced_and_api_cannot_access_custody() -> None:
    asyncio.run(exercise())


async def exercise() -> None:
    admin = make_engine(os.environ["AEGENTRA_TEST_ADMIN_URL"])
    app = make_engine(os.environ["AEGENTRA_TEST_APP_URL"])
    bridge = make_engine(os.environ["AEGENTRA_TEST_BRIDGE_URL"])
    factory = async_sessionmaker(bridge, expire_on_commit=False)
    org, other, actor, asset, upload, job = (uuid4() for _ in range(6))
    now = datetime.now(timezone.utc)
    nonce = "n" * 43
    pinned = dict(
        org_id=org, job_id=job, actor_id=actor, generation=1,
    )
    kwargs = dict(
        **pinned, nonce=nonce, input_sha256=b"i" * 32,
        toolchain_sha256=b"t" * 32, account_id="123456789012",
        ami_id="ami-00000000000000001",
        availability_zone="us-east-1a", subnet_id="subnet-offline",
        security_group_id="sg-offline",
        kms_key_arn="arn:aws:kms:us-east-1:123456789012:key/test", now=now,
    )
    try:
        async with admin.begin() as s:
            await s.execute(insert(Organization), [
                {"id": org, "slug": f"guest-{org.hex}"},
                {"id": other, "slug": f"guest-{other.hex}"},
            ])
            await s.execute(insert(Identity).values(
                id=actor, org_id=org, issuer="https://idp.test",
                subject="bridge", role="EDITOR", active=True,
                membership_version=1,
            ))
            await s.execute(insert(Asset).values(
                org_id=org, id=asset, slug="offline", criticality="LOW",
            ))
            await s.execute(insert(StagingUpload).values(
                org_id=org, id=upload, asset_id=asset, issued_by=actor,
                content_digest=b"a" * 32, content_manifest={},
                status="AWAITING_VERIFICATION", created_at=now,
                expires_at=now + timedelta(minutes=15),
            ))
            await s.execute(insert(ScanJob).values(
                org_id=org, id=job, upload_id=upload,
                status="LEASED", created_at=now, attempts=1,
                attempt_generation=1, lease_nonce=nonce,
                lease_expires=now + timedelta(seconds=90),
                attempt_deadline=now + timedelta(minutes=8),
            ))
        async with organization_session(factory, org) as s:
            with pytest.raises(BridgeConflict, match="stale"):
                await reserve_attempt(s, **{**kwargs, "nonce": "wrong"})
            with pytest.raises(BridgeConflict, match="AMI"):
                await reserve_attempt(s, **{**kwargs, "ami_id": "ami-unqualified"})
            await reserve_attempt(s, **kwargs)
        async with organization_session(factory, org) as s:
            with pytest.raises(BridgeConflict, match="already"):
                await reserve_attempt(s, **kwargs)
            await record_volumes(
                s, **pinned, input_volume_id="vol-00000000000000001",
                output_volume_id="vol-00000000000000002", now=now,
            )
            await record_instance(
                s, **pinned, instance_id="i-00000000000000001", now=now,
            )
        # The bridge role can update state, but must never rewrite pinned
        # AMI, account, toolchain or other physical identities after reserve.
        with pytest.raises(DBAPIError, match="guest physical pin immutable"):
            async with organization_session(factory, org) as s:
                await s.execute(update(GuestAttempt).where(
                    GuestAttempt.org_id == org, GuestAttempt.job_id == job,
                    GuestAttempt.generation == 1,
                ).values(ami_id="ami-00000000000000002"))
        with pytest.raises(DBAPIError, match="guest custody state transition"):
            async with organization_session(factory, org) as s:
                await s.execute(update(GuestAttempt).where(
                    GuestAttempt.org_id == org, GuestAttempt.job_id == job,
                    GuestAttempt.generation == 1,
                ).values(state="DISPOSED"))
        async with organization_session(factory, other) as s:
            assert (await s.scalars(select(GuestAttempt))).all() == []
        app_sessions = async_sessionmaker(app)
        with pytest.raises(DBAPIError, match="permission denied"):
            async with organization_session(app_sessions, org) as s:
                await s.execute(select(GuestAttempt))

        tags = [
            {"Key": "AegentraJob", "Value": str(job)},
            {"Key": "AegentraGeneration", "Value": "1"},
        ]
        inst = {
            "InstanceId": "i-00000000000000001",
            "ImageId": kwargs["ami_id"], "State": {"Name": "terminated"},
            "SubnetId": "subnet-offline",
            "Placement": {"AvailabilityZone": "us-east-1a"},
            "MetadataOptions": {"HttpEndpoint": "disabled"},
            "SecurityGroups": [{"GroupId": "sg-offline"}],
            "NetworkInterfaces": [{"SubnetId": "subnet-offline"}],
            "Tags": tags,
        }
        vols = [
            {
                "VolumeId": vol, "State": "available", "Attachments": [],
                "Encrypted": True, "AvailabilityZone": "us-east-1a",
                "KmsKeyId": kwargs["kms_key_arn"], "Tags": tags,
            }
            for vol in ("vol-00000000000000001", "vol-00000000000000002")
        ]
        first_detach = DetachedInventory(
            kwargs["account_id"], now + timedelta(seconds=30),
            (inst,), tuple(vols),
        )
        second_detach = DetachedInventory(
            kwargs["account_id"], now + timedelta(seconds=60),
            (inst,), tuple(vols),
        )
        async with organization_session(factory, org) as s:
            with pytest.raises(CustodyError):
                await record_verified_detach(
                    s, **pinned, now=now + timedelta(seconds=65),
                    first=first_detach, second=first_detach,
                )
            result = await record_verified_detach(
                s, **pinned, now=now + timedelta(seconds=65),
                first=first_detach, second=second_detach,
            )
            assert result.job_id == job
        async with admin.connect() as s:
            attempt = (await s.execute(
                select(GuestAttempt).where(GuestAttempt.job_id == job)
            )).one()
            assert attempt.state == "DETACHED_VERIFIED"
            assert len((await s.execute(
                select(GuestResource).where(GuestResource.job_id == job)
            )).all()) == 3
        async with admin.begin() as s:
            await s.execute(insert(ScanReceipt).values(
                org_id=org, job_id=job, generation=1,
                result_sha256=b"r" * 32, source_sha256=b"i" * 32,
                toolchain_sha256=b"t" * 32, status="COMPLETE",
                coverage="VERIFIED", finding_count=0,
                created_at=now,
            ))
        # Custody timestamps must never move backwards after detach.
        # The raw volumes may not be deleted before a durable delete intent
        # and advisory receipt are committed.
        with pytest.raises(DBAPIError, match="guest custody clock"):
            async with organization_session(factory, org) as s:
                await begin_guest_disposal(
                    s, **pinned, now=now,
                )
        async with organization_session(factory, org) as s:
            assert await begin_guest_disposal(
                s, **pinned, now=now + timedelta(seconds=65),
            ) == "DELETE_REQUESTED"
        async with organization_session(factory, org) as s:
            assert await begin_guest_disposal(
                s, **pinned, now=now + timedelta(seconds=65),
            ) == "DELETE_REQUESTED"
        first = DeletedInventory(
            account_id=kwargs["account_id"],
            observed_at=now + timedelta(seconds=30),
            instance_id="i-00000000000000001",
            instance_state="terminated",
            volume_states={
                "vol-00000000000000001": "not-found",
                "vol-00000000000000002": "not-found",
            },
        )
        second = DeletedInventory(
            account_id=kwargs["account_id"],
            observed_at=now + timedelta(seconds=60),
            instance_id=first.instance_id,
            instance_state="not-found",
            volume_states=first.volume_states,
        )
        async with organization_session(factory, org) as s:
            with pytest.raises(DisposalRejected):
                await record_verified_disposal(
                    s, **pinned, first=first,
                    second=first, now=now + timedelta(seconds=61),
                )
            assert await record_verified_disposal(
                s, **pinned, first=first, second=second,
                now=now + timedelta(seconds=65),
            ) == "DISPOSED"
        async with organization_session(factory, org) as s:
            assert await record_verified_disposal(
                s, **pinned, first=first, second=second,
                now=now + timedelta(seconds=65),
            ) == "DISPOSED"
        async with admin.connect() as s:
            result = (await s.execute(
                select(GuestAttempt).where(GuestAttempt.job_id == job)
            )).one()
            assert result.state == "DISPOSED"
    finally:
        try:
            async with admin.begin() as s:
                await s.execute(delete(OutboxEvent).where(OutboxEvent.org_id == org))
                await s.execute(delete(AuditEntry).where(AuditEntry.org_id == org))
                await s.execute(delete(AuditStream).where(AuditStream.org_id == org))
                await s.execute(delete(ScanReceipt).where(ScanReceipt.org_id == org))
                await s.execute(delete(GuestResource).where(GuestResource.org_id == org))
                await s.execute(delete(GuestAttempt).where(GuestAttempt.org_id == org))
                await s.execute(delete(ScanJob).where(ScanJob.org_id == org))
                await s.execute(delete(StagingUpload).where(StagingUpload.org_id == org))
                await s.execute(delete(Asset).where(Asset.org_id == org))
                await s.execute(delete(Identity).where(Identity.org_id == org))
                await s.execute(delete(Organization).where(Organization.id.in_([org, other])))
        finally:
            await bridge.dispose()
            await app.dispose()
            await admin.dispose()
