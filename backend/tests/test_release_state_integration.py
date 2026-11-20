"""Native PostgreSQL authority test: two reviewers, shadow grant, fencing, STOP.

The test deliberately never enables ENFORCED or publishes customer bytes.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import delete, insert, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker

from aegentra.db import (
    Asset, AuditEntry, AuditStream, Identity, Organization, OutboxEvent,
    ReleaseEndorsement, ReleaseGrant, ReleaseOrgGuard, ReleaseSelection,
    ReleaseTarget,
)
from aegentra.persistence import make_engine, organization_session
from aegentra.release_state import (
    ReleaseConflict, enroll_shadow_target, issue_shadow_grant, redeem_shadow_grant,
    release_session, set_target_guard,
)
from aegentra.review_crypto import (
    EndorsementBody, ReviewSubject, ReviewerCredential,
    SignedEndorsement, endorsement_message,
)
from aegentra.staging_proof import StagingProof, stage_message


def signed_fixtures(org, asset, target, incarnation, now, submitter):
    subject = ReviewSubject(
        kind="aegentra.review.subject.v1", org_id=org, asset_id=asset,
        target_id=target, incarnation=incarnation,
        destination_host="origin.example.test", resource_path="/index.html",
        content_sha256="a" * 64, storage_sha256="b" * 64,
        independent_bytes_sha256="a" * 64,
        delivery_profile_sha256="c" * 64,
        policy_sha256="d" * 64, baseline_sha256="e" * 64,
        source_attestation_sha256="f" * 64,
        scan_receipt_sha256="1" * 64, change_request_sha256="2" * 64,
        baseline_revision=1, prior_published_revision=0,
        org_epoch=1, target_epoch=1, submitter_person_id=submitter,
    )
    registry = {}
    endorsements = []
    for n in (1, 2):
        key = Ed25519PrivateKey.generate()
        person = uuid4()
        credential = ReviewerCredential(
            person_id=person, key_id=f"hardware-key-{n}",
            custody_group=f"independent-group-{n}",
            enrollment_generation=1,
            public_ed25519=key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw,
            ), independently_verified=True,
        )
        registry[credential.key_id] = credential
        body = EndorsementBody(
            kind="aegentra.review.endorsement.v1",
            subject_sha256=subject.digest(), person_id=person,
            key_id=credential.key_id, custody_group=credential.custody_group,
            challenge_nonce=str(n) * 43, enrollment_generation=1,
            audience="aegentra-independent-review", action="ENDORSE_FINAL_BYTES",
            issued_at=now - timedelta(seconds=1),
            expires_at=now + timedelta(minutes=3),
        )
        endorsements.append(
            SignedEndorsement(body, key.sign(endorsement_message(body)))
        )
    verifier_key = Ed25519PrivateKey.generate()
    verifier_public = verifier_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    stage = StagingProof(
        kind="aegentra.release.staging-proof.v1",
        audience="aegentra-authority-redeem",
        incarnation=incarnation, org_id=org, target_id=target,
        subject_sha256=subject.digest(), content_sha256=subject.content_sha256,
        storage_sha256=subject.storage_sha256,
        delivery_profile_sha256=subject.delivery_profile_sha256,
        prior_published_revision=0, verifier_key_id="trusted-verifier-1",
        issued_at=now, expires_at=now + timedelta(seconds=90),
    )
    return subject, tuple(endorsements), registry, stage, verifier_public, verifier_key.sign(stage_message(stage))


@pytest.mark.skipif(
    not all(os.getenv(name) for name in (
        "AEGENTRA_TEST_ADMIN_URL", "AEGENTRA_TEST_APP_URL",
        "AEGENTRA_TEST_RELEASE_URL",
    )), reason="native PostgreSQL release-authority role not configured",
)
def test_serialized_shadow_grant_redemption_and_stop() -> None:
    asyncio.run(_exercise())


async def _exercise() -> None:
    admin = make_engine(os.environ["AEGENTRA_TEST_ADMIN_URL"])
    app = make_engine(os.environ["AEGENTRA_TEST_APP_URL"])
    authority = make_engine(os.environ["AEGENTRA_TEST_RELEASE_URL"])
    sessions = async_sessionmaker(authority, expire_on_commit=False)
    org, other, asset, target, incarnation, submitter = (uuid4() for _ in range(6))
    now = datetime.now(timezone.utc)
    clk = lambda: now
    try:
        async with admin.begin() as s:
            await s.execute(insert(Organization), [
                {"id": org, "slug": f"release-{org.hex}"},
                {"id": other, "slug": f"release-{other.hex}"},
            ])
            await s.execute(insert(Identity).values(
                id=submitter, org_id=org, issuer="https://idp.test",
                subject="release-owner", role="EDITOR",
                active=True, membership_version=1,
            ))
            await s.execute(insert(Asset).values(
                org_id=org, id=asset,
                slug="controlled-origin", criticality="HIGH",
            ))
            await s.execute(insert(ReleaseOrgGuard).values(
                org_id=org, incarnation=incarnation, epoch=1,
            ))

        async with release_session(sessions, org) as s:
            await enroll_shadow_target(
                s, org_id=org, target_id=target, asset_id=asset,
                destination_host="origin.example.test", resource_path="/index.html", actor_id=submitter,
            )

        subject, endorsements, registry, stage, vkey, signature = signed_fixtures(
            org, asset, target, incarnation, now, submitter,
        )
        async with release_session(sessions, org) as s:
            granted = await issue_shadow_grant(
                s, subject=subject, endorsements=endorsements,
                enrolled=registry, actor_id=submitter, clock=clk,
            )
            assert granted.expires_at <= now + timedelta(seconds=60)

        async with release_session(sessions, org) as s:
            seq, state = await redeem_shadow_grant(
                s, subject=subject, nonce=granted.nonce,
                proof=stage, proof_signature=signature,
                verifier_public_key=vkey, verifier_key_id="trusted-verifier-1",
                actor_id=submitter, clock=clk,
            )
            assert (seq, state) == (1, "SELECTED_UNWITNESSED")
        async with release_session(sessions, org) as s:
            seq2, state2 = await redeem_shadow_grant(
                s, subject=subject, nonce=granted.nonce,
                proof=stage, proof_signature=signature,
                verifier_public_key=vkey, verifier_key_id="trusted-verifier-1",
                actor_id=submitter, clock=clk,
            )
            assert (seq2, state2) == (1, "SELECTED_UNWITNESSED")

        # Ordinary API cannot even inspect the authority's grant ledger.
        with pytest.raises(DBAPIError, match="permission denied"):
            async with organization_session(async_sessionmaker(app), org) as s:
                await s.execute(select(ReleaseGrant))

        async with release_session(sessions, other) as s:
            assert (await s.scalars(select(ReleaseTarget))).all() == []

        async with release_session(sessions, org) as s:
            frozen_epoch = await set_target_guard(
                s, org_id=org, target_id=target,
                actor_id=submitter, new_guard="HOLD_PROMOTION",
            )
            assert frozen_epoch == 2

        async with release_session(sessions, org) as s:
            stopped_epoch = await set_target_guard(
                s, org_id=org, target_id=target,
                actor_id=submitter, new_guard="STOP_SERVING",
            )
            assert stopped_epoch == 3
            with pytest.raises(ReleaseConflict):
                await set_target_guard(
                    s, org_id=org, target_id=target,
                    actor_id=submitter, new_guard="HOLD_PROMOTION",
                )

        with pytest.raises(ReleaseConflict, match="not currently authorized"):
            async with release_session(sessions, org) as s:
                await redeem_shadow_grant(
                    s, subject=subject, nonce=granted.nonce,
                    proof=stage, proof_signature=signature,
                    verifier_public_key=vkey,
                    verifier_key_id="trusted-verifier-1",
                    actor_id=submitter, clock=clk,
                )

        async with admin.connect() as s:
            targets = (await s.execute(
                select(ReleaseTarget).where(ReleaseTarget.org_id == org)
            )).all()
            selections = (await s.execute(
                select(ReleaseSelection).where(ReleaseSelection.org_id == org)
            )).all()
            reviews = (await s.execute(
                select(ReleaseEndorsement).where(ReleaseEndorsement.org_id == org)
            )).all()
            assert len(targets) == len(selections) == 1
            assert len(reviews) == 2
            assert targets[0].guard == "STOP_SERVING"
            assert targets[0].next_attempt_sequence == 1
            assert targets[0].published_revision == 0
            assert selections[0].state == "SELECTED_UNWITNESSED"
    finally:
        try:
            async with admin.begin() as s:
                await s.execute(delete(OutboxEvent).where(OutboxEvent.org_id == org))
                await s.execute(delete(AuditEntry).where(AuditEntry.org_id == org))
                await s.execute(delete(AuditStream).where(AuditStream.org_id == org))
                await s.execute(delete(ReleaseSelection).where(ReleaseSelection.org_id == org))
                await s.execute(delete(ReleaseGrant).where(ReleaseGrant.org_id == org))
                await s.execute(delete(ReleaseEndorsement).where(ReleaseEndorsement.org_id == org))
                await s.execute(delete(ReleaseTarget).where(ReleaseTarget.org_id == org))
                await s.execute(delete(ReleaseOrgGuard).where(ReleaseOrgGuard.org_id == org))
                await s.execute(delete(Asset).where(Asset.org_id == org))
                await s.execute(delete(Identity).where(Identity.org_id == org))
                await s.execute(delete(Organization).where(Organization.id.in_([org, other])))
        finally:
            await authority.dispose()
            await app.dispose()
            await admin.dispose()
