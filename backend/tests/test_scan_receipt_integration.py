"""Native PostgreSQL validator role: receipt is immutable and never release authority."""
from __future__ import annotations

import asyncio
import hashlib
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker

from aegentra.db import (
    Asset, AuditEntry, AuditStream, GuestAttempt, Identity,
    Organization, OutboxEvent, ScanJob, ScanReceipt, StagingUpload,
)
from aegentra.guest_protocol import GuestRequest, encode_input
from aegentra.offline_guest import analyze_frame
from aegentra.persistence import make_engine, organization_session
from aegentra.scan_receipts import ReceiptConflict, record_validated_receipt


@pytest.mark.skipif(
    not all(os.getenv(name) for name in (
        "AEGENTRA_TEST_ADMIN_URL", "AEGENTRA_TEST_APP_URL",
        "AEGENTRA_TEST_VALIDATOR_URL",
    )),
    reason="separate native validator database role not provided",
)
def test_only_validator_writes_scoped_advisory_receipt() -> None:
    asyncio.run(exercise())


async def exercise() -> None:
    admin = make_engine(os.environ["AEGENTRA_TEST_ADMIN_URL"])
    app = make_engine(os.environ["AEGENTRA_TEST_APP_URL"])
    validator = make_engine(os.environ["AEGENTRA_TEST_VALIDATOR_URL"])
    factory = async_sessionmaker(validator, expire_on_commit=False)
    now = datetime.now(timezone.utc)
    org, other, actor, asset, upload, job = (uuid4() for _ in range(6))
    source = b"const answer = 42;"
    nonce = "n" * 43
    expected = GuestRequest(
        kind="aegentra.guest.input.v1", org_id=org, job_id=job,
        generation=3, nonce=nonce, toolchain_sha256="a" * 64,
        source_sha256=hashlib.sha256(source).hexdigest(), byte_length=len(source),
    )
    result = analyze_frame(encode_input(expected, source))
    digest = hashlib.sha256(result).digest()
    try:
        async with admin.begin() as s:
            await s.execute(insert(Organization), [
                {"id": org, "slug": f"receipt-{org.hex}"},
                {"id": other, "slug": f"receipt-{other.hex}"},
            ])
            await s.execute(insert(Identity).values(
                id=actor, org_id=org, issuer="https://idp.test",
                subject="validator", role="EDITOR", active=True,
                membership_version=1,
            ))
            await s.execute(insert(Asset).values(
                org_id=org, id=asset, slug="validator-asset", criticality="LOW",
            ))
            await s.execute(insert(StagingUpload).values(
                org_id=org, id=upload, asset_id=asset, issued_by=actor,
                content_digest=b"a" * 32, content_manifest={},
                status="AWAITING_VERIFICATION", created_at=now,
                expires_at=now + timedelta(minutes=15),
            ))
            await s.execute(insert(ScanJob).values(
                org_id=org, id=job, upload_id=upload,
                status="PENDING_TRUSTED_VALIDATION", created_at=now,
                attempt_generation=3, attempts=3, result_sha256=digest,
            ))
            await s.execute(insert(GuestAttempt).values(
                org_id=org, job_id=job, generation=3,
                nonce_sha256=hashlib.sha256(nonce.encode()).digest(),
                input_sha256=bytes.fromhex(expected.source_sha256),
                toolchain_sha256=bytes.fromhex(expected.toolchain_sha256),
                ami_id="ami-00000000000000001",
                account_id="123456789012", availability_zone="us-east-1a",
                subnet_id="subnet-fixture", security_group_id="sg-fixture",
                kms_key_arn="arn:aws:kms:us-east-1:123456789012:key/test",
                state="DETACHED_VERIFIED", created_at=now, updated_at=now,
            ))

        async with organization_session(factory, org) as s:
            lead = await record_validated_receipt(
                s, expected=expected, original_source=source,
                raw_result=result, actor_id=actor, now=now,
            )
            assert lead.disposition == "ADVISORY_PENDING_INDEPENDENT_REVIEW"
        # An older attempt without a pinned AMI is not eligible even if
        # it already has a synthetic detached state and advisory receipt.
        async with admin.begin() as s:
            await s.execute(update(GuestAttempt).where(
                GuestAttempt.org_id == org, GuestAttempt.job_id == job,
                GuestAttempt.generation == 3,
            ).values(ami_id=None))
        async with organization_session(factory, org) as s:
            with pytest.raises(ReceiptConflict, match="incomplete physical"):
                await record_validated_receipt(
                    s, expected=expected, original_source=source,
                    raw_result=result, actor_id=actor, now=now,
                )
        async with admin.begin() as s:
            await s.execute(update(GuestAttempt).where(
                GuestAttempt.org_id == org, GuestAttempt.job_id == job,
                GuestAttempt.generation == 3,
            ).values(ami_id="ami-00000000000000001"))
        async with organization_session(factory, org) as s:
            same = await record_validated_receipt(
                s, expected=expected, original_source=source,
                raw_result=result, actor_id=actor, now=now,
            )
            assert same == lead
            with pytest.raises(ReceiptConflict):
                await record_validated_receipt(
                    s, expected=expected.model_copy(update={"nonce": "x" * 43}),
                    original_source=source, raw_result=result, actor_id=actor, now=now,
                )

        async with organization_session(factory, other) as s:
            assert (await s.scalars(select(ScanReceipt))).all() == []
        app_factory = async_sessionmaker(app)
        with pytest.raises(DBAPIError, match="permission denied"):
            async with organization_session(app_factory, org) as s:
                await s.execute(select(ScanReceipt))
        async with admin.connect() as s:
            receipts = (await s.execute(
                select(ScanReceipt).where(ScanReceipt.org_id == org)
            )).all()
            events = (await s.execute(
                select(AuditEntry).where(AuditEntry.org_id == org)
            )).all()
            assert len(receipts) == len(events) == 1
            assert receipts[0].coverage == "VERIFIED"
    finally:
        try:
            async with admin.begin() as s:
                await s.execute(delete(OutboxEvent).where(OutboxEvent.org_id == org))
                await s.execute(delete(AuditEntry).where(AuditEntry.org_id == org))
                await s.execute(delete(AuditStream).where(AuditStream.org_id == org))
                await s.execute(delete(ScanReceipt).where(ScanReceipt.org_id == org))
                await s.execute(delete(GuestAttempt).where(GuestAttempt.org_id == org))
                await s.execute(delete(ScanJob).where(ScanJob.org_id == org))
                await s.execute(delete(StagingUpload).where(StagingUpload.org_id == org))
                await s.execute(delete(Asset).where(Asset.org_id == org))
                await s.execute(delete(Identity).where(Identity.org_id == org))
                await s.execute(delete(Organization).where(Organization.id.in_([org, other])))
        finally:
            await validator.dispose()
            await app.dispose()
            await admin.dispose()
