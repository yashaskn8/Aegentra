"""Native PostgreSQL observer-role isolation and revision-scoped STOP/HOLD."""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker

from aegentra.db import (
    Asset, AuditEntry, AuditStream, Identity, Organization, OutboxEvent,
    ReleaseGrant, ReleaseOrgGuard, ReleaseObservation, ReleasePublication,
    ReleaseSelection, ReleaseTarget,
)
from aegentra.observation_crypto import (
    ObservationBody, ObservationRejected, ObserverCredential,
    SignedObservation, observation_message,
)
from aegentra.observation_state import (
    hold_if_observation_overdue, record_observation,
)
from aegentra.persistence import make_engine, organization_session
from aegentra.release_state import release_session


@pytest.mark.skipif(
    not all(os.getenv(key) for key in (
        "AEGENTRA_TEST_ADMIN_URL", "AEGENTRA_TEST_OBSERVER_URL",
        "AEGENTRA_TEST_APP_URL",
    )),
    reason="native PostgreSQL observer identity not configured",
)
def test_independent_observer_fences_only_current_proven_mismatch() -> None:
    asyncio.run(_exercise())


async def _exercise() -> None:
    admin = make_engine(os.environ["AEGENTRA_TEST_ADMIN_URL"])
    observer = make_engine(os.environ["AEGENTRA_TEST_OBSERVER_URL"])
    web_api = make_engine(os.environ["AEGENTRA_TEST_APP_URL"])
    sessions = async_sessionmaker(observer, expire_on_commit=False)
    org, other, asset, target, actor, incarnation = (uuid4() for _ in range(6))
    now = datetime.now(timezone.utc)
    start = now - timedelta(seconds=10)
    grant_nonce = b"n" * 32
    key = ec.generate_private_key(ec.SECP256R1())
    credential = ObserverCredential(
        key_id="separate-observer-credential",
        public_key_der=key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        independently_enrolled=True,
    )

    def sign(
        *, measured_at=now, status=200, complete=True,
        observed="a" * 64, profile="b" * 64,
    ) -> SignedObservation:
        body = ObservationBody(
            kind="aegentra.observer.readback.v1",
            audience="aegentra-release-observer",
            observation_id=uuid4(), incarnation=incarnation,
            org_id=org, target_id=target,
            host="static.example.test", resource_path="/index.html",
            published_revision=1, attempt_sequence=3,
            cohort="edge-one", observer_key_id=credential.key_id,
            expected_sha256="a" * 64, observed_sha256=observed,
            expected_profile_sha256="b" * 64,
            observed_profile_sha256=profile,
            http_status=status, complete_bytes=complete,
            measured_at=measured_at, signed_at=measured_at,
        )
        return SignedObservation(
            body, key.sign(observation_message(body), ec.ECDSA(hashes.SHA256())),
        )

    try:
        async with admin.begin() as s:
            await s.execute(insert(Organization), [
                {"id": org, "slug": f"observe-{org.hex}"},
                {"id": other, "slug": f"observe-{other.hex}"},
            ])
            await s.execute(insert(Identity).values(
                id=actor, org_id=org, issuer="https://idp.example.test",
                subject="observer-service", role="ANALYST",
                active=True, membership_version=1,
            ))
            await s.execute(insert(Asset).values(
                org_id=org, id=asset,
                slug="static-origin", criticality="HIGH",
            ))
            await s.execute(insert(ReleaseOrgGuard).values(
                org_id=org, incarnation=incarnation, epoch=1,
            ))
            await s.execute(insert(ReleaseTarget).values(
                org_id=org, id=target, asset_id=asset,
                destination_host="static.example.test",
                resource_path="/index.html",
                mode="ENFORCED", guard="ACTIVE", epoch=1,
                next_attempt_sequence=3, published_revision=1,
                published_attempt_sequence=3,
            ))
            await s.execute(insert(ReleaseGrant).values(
                org_id=org, target_id=target, nonce_hash=grant_nonce,
                subject_sha256=b"s" * 32, subject_body={},
                approval_set_sha256=b"p" * 32,
                incarnation=incarnation, org_epoch=1, target_epoch=1,
                expected_prior_revision=0, status="REDEEMED",
                issued_at=start, expires_at=now + timedelta(minutes=1),
                selection_sequence=3,
            ))
            await s.execute(insert(ReleaseSelection).values(
                org_id=org, target_id=target, attempt_sequence=3,
                grant_nonce_hash=grant_nonce, subject_sha256=b"s" * 32,
                staging_sha256=b"t" * 32, prior_published_revision=0,
                state="PUBLISHED", created_at=start,
                expires_at=now + timedelta(minutes=1),
            ))
            await s.execute(insert(ReleasePublication).values(
                org_id=org, target_id=target,
                published_revision=1, attempt_sequence=3,
                witness_version_id="witness-v1",
                witness_sha256=b"w" * 32,
                representation_sha256=bytes.fromhex("a" * 64),
                delivery_profile_sha256=bytes.fromhex("b" * 64),
                created_at=start, status="SEALED",
                origin_bucket="pinned-origin",
                origin_key="published/v1", origin_version_id="exact-v1",
                receipt_version_id="exact-receipt-v1",
                receipt_sha256=b"r" * 32,
            ))

        with pytest.raises(DBAPIError, match="permission denied"):
            async with organization_session(
                async_sessionmaker(web_api), org
            ) as s:
                await s.execute(select(ReleaseObservation))

        async with release_session(sessions, other) as s:
            assert (await s.scalars(select(ReleaseObservation))).all() == []

        # A signed delayed measurement must not stop a healthy current release.
        historical = sign(measured_at=now - timedelta(minutes=2), observed="f" * 64)
        async with release_session(sessions, org) as s:
            assert await record_observation(
                s, envelope=historical, observer=credential,
                actor_id=actor, now=now,
            ) == "HISTORICAL"

        # Signature substitution is rejected before any state change.
        forged = sign(observed="f" * 64)
        with pytest.raises(ObservationRejected):
            async with release_session(sessions, org) as s:
                await record_observation(
                    s, envelope=SignedObservation(forged.body, b"x" * 70),
                    observer=credential, actor_id=actor, now=now,
                )

        async with release_session(sessions, org) as s:
            assert await hold_if_observation_overdue(
                s, org_id=org, target_id=target, actor_id=actor,
                now=now + timedelta(minutes=6),
            )
        async with admin.connect() as s:
            row = (await s.execute(select(ReleaseTarget).where(
                ReleaseTarget.org_id == org
            ))).one()
            assert row.guard == "HOLD_PROMOTION"

        # Even in HOLD, current byte mismatches take the stronger STOP.
        mismatch = sign(observed="f" * 64)
        async with release_session(sessions, org) as s:
            assert await record_observation(
                s, envelope=mismatch, observer=credential,
                actor_id=actor, now=now,
            ) == "CURRENT_MISMATCH"
        async with release_session(sessions, org) as s:
            with pytest.raises(ObservationRejected, match="consumed"):
                await record_observation(
                    s, envelope=mismatch, observer=credential,
                    actor_id=actor, now=now,
                )

        async with admin.connect() as s:
            row = (await s.execute(select(ReleaseTarget).where(
                ReleaseTarget.org_id == org
            ))).one()
            records = (await s.execute(select(ReleaseObservation).where(
                ReleaseObservation.org_id == org
            ))).all()
            assert row.guard == "STOP_SERVING"
            assert row.epoch == 3
            assert len(records) == 2
            assert {r.disposition for r in records} == {
                "HISTORICAL", "CURRENT_MISMATCH",
            }
    finally:
        try:
            async with admin.begin() as s:
                await s.execute(delete(OutboxEvent).where(OutboxEvent.org_id == org))
                await s.execute(delete(AuditEntry).where(AuditEntry.org_id == org))
                await s.execute(delete(AuditStream).where(AuditStream.org_id == org))
                await s.execute(delete(ReleaseObservation).where(
                    ReleaseObservation.org_id == org
                ))
                await s.execute(delete(ReleasePublication).where(
                    ReleasePublication.org_id == org
                ))
                await s.execute(delete(ReleaseSelection).where(
                    ReleaseSelection.org_id == org
                ))
                await s.execute(delete(ReleaseGrant).where(
                    ReleaseGrant.org_id == org
                ))
                await s.execute(delete(ReleaseTarget).where(
                    ReleaseTarget.org_id == org
                ))
                await s.execute(delete(ReleaseOrgGuard).where(
                    ReleaseOrgGuard.org_id == org
                ))
                await s.execute(delete(Asset).where(Asset.org_id == org))
                await s.execute(delete(Identity).where(Identity.org_id == org))
                await s.execute(delete(Organization).where(
                    Organization.id.in_([org, other])
                ))
        finally:
            await observer.dispose()
            await web_api.dispose()
            await admin.dispose()
