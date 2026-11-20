"""Native PostgreSQL witnessed release and private publish boundary.

Admin fixture simulates an explicitly enrolled ENFORCED target only in CI.
No real AWS release is enabled or deployed by these tests.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import delete, insert, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker

from aegentra.db import (
    Asset, AuditEntry, AuditStream, Identity, Organization, OutboxEvent,
    ReleaseEndorsement, ReleaseGrant, ReleaseOrgGuard, ReleaseSelection,
    ReleaseTarget, ReleasePublication,
)
from aegentra.gateway_signatures import VetoSnapshot, SignedVeto, veto_message
from aegentra.origin_binding import OriginBinding, origin_message
from aegentra.persistence import make_engine
from aegentra.release_state import (
    ReleaseConflict, enroll_shadow_target, issue_shadow_grant,
    redeem_shadow_grant, release_session,
)
from aegentra.release_publication import publish_witnessed_selection
from aegentra.witness_crypto import (
    WitnessBody, WitnessArchiveRef, signed_certificate_bytes, witness_message,
)
from aegentra.witness_registration import witness_committed_selection
from aegentra.publication_receipt import (
    PublicationReceipt, publication_receipt_message,
    signed_publication_receipt_bytes,
)
from aegentra.publication_archive import PublicationArchiveRef
from aegentra.publication_seal import seal_publication_receipt
from aegentra.head_service import KmsHeadSigner, read_primary_head
from aegentra.gateway_signatures import verify_head
from test_release_state_integration import signed_fixtures


def public(key):
    return key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


@pytest.mark.skipif(
    not all(os.getenv(name) for name in (
        "AEGENTRA_TEST_ADMIN_URL", "AEGENTRA_TEST_RELEASE_URL",
    )), reason="native PostgreSQL authority URL missing",
)
def test_signed_witness_then_guarded_publication() -> None:
    asyncio.run(_exercise())


async def _exercise():
    admin = make_engine(os.environ["AEGENTRA_TEST_ADMIN_URL"])
    authority = make_engine(os.environ["AEGENTRA_TEST_RELEASE_URL"])
    sessions = async_sessionmaker(authority, expire_on_commit=False)
    org, other, asset, target, incarnation, submitter = (uuid4() for _ in range(6))
    now = datetime.now(timezone.utc)
    clock = lambda: now
    try:
        async with admin.begin() as s:
            await s.execute(insert(Organization), [
                {"id": org, "slug": f"witness-{org.hex}"},
                {"id": other, "slug": f"witness-{other.hex}"},
            ])
            await s.execute(insert(Identity).values(
                id=submitter, org_id=org, issuer="https://idp.test",
                subject="witness-owner", role="EDITOR",
                active=True, membership_version=1,
            ))
            await s.execute(insert(Asset).values(
                org_id=org, id=asset,
                slug="target", criticality="HIGH",
            ))
            await s.execute(insert(ReleaseOrgGuard).values(
                org_id=org, incarnation=incarnation, epoch=1,
            ))
        async with release_session(sessions, org) as s:
            await enroll_shadow_target(
                s, org_id=org, target_id=target, asset_id=asset,
                destination_host="origin.example.test", actor_id=submitter,
            )
        subject, endorsements, registry, stage, verifier_pub, stage_sig = signed_fixtures(
            org, asset, target, incarnation, now, submitter,
        )
        async with release_session(sessions, org) as s:
            grant = await issue_shadow_grant(
                s, subject=subject, endorsements=endorsements,
                enrolled=registry, actor_id=submitter, clock=clock,
            )
        async with release_session(sessions, org) as s:
            seq, state = await redeem_shadow_grant(
                s, subject=subject, nonce=grant.nonce,
                proof=stage, proof_signature=stage_sig,
                verifier_public_key=verifier_pub, verifier_key_id="trusted-verifier-1",
                actor_id=submitter, clock=clock,
            )
            assert seq == 1 and state == "SELECTED_UNWITNESSED"
        async with admin.connect() as s:
            selection = (await s.execute(select(ReleaseSelection).where(
                ReleaseSelection.org_id == org,
                ReleaseSelection.target_id == target,
                ReleaseSelection.attempt_sequence == seq,
            ))).one()

        witness_signer = ec.generate_private_key(ec.SECP256R1())
        veto_signer = ec.generate_private_key(ec.SECP256R1())
        origin_signer = ec.generate_private_key(ec.SECP256R1())
        witness = WitnessBody(
            kind="aegentra.security.witness.v1",
            audience="aegentra-release-publication",
            incarnation=incarnation, org_id=org, target_id=target,
            attempt_sequence=seq, prior_published_revision=0,
            predecessor_witness_sha256="0" * 64,
            subject_sha256=subject.digest(),
            approval_set_sha256=grant.approval_set_sha256,
            staging_sha256=hashlib.sha256(
                b"aegentra.release.staging-record.v1\x00"
                + stage.canonical() + stage_sig
            ).hexdigest(),
            content_sha256=subject.content_sha256,
            delivery_profile_sha256=subject.delivery_profile_sha256,
            fixed_bundle_sha256=subject.fixed_bundle_sha256,
            security_root_generation=3,
            issued_at=now, selection_deadline=selection.expires_at,
        )
        wsig = witness_signer.sign(witness_message(witness), ec.ECDSA(hashes.SHA256()))
        doc = signed_certificate_bytes(witness, wsig)
        ref = WitnessArchiveRef(
            bucket="independent-security-archive",
            key=(
                f"certificates/v1/{org.hex}/{incarnation.hex}/"
                f"{target.hex}/{seq:020d}"
            ),
            version_id="independent-s3-version-one",
            object_sha256=hashlib.sha256(doc).hexdigest(),
        )
        nonce = "q" * 43
        veto_body = VetoSnapshot(
            kind="aegentra.security.veto-state.v1",
            audience="aegentra-protected-gateway",
            request_nonce=nonce, org_id=org,
            incarnation=incarnation, root_generation=3,
            veto_generation=0, state="CLEAR",
            issued_at=now, expires_at=now + timedelta(seconds=1),
        )
        veto = SignedVeto(
            veto_body, veto_signer.sign(
                veto_message(veto_body), ec.ECDSA(hashes.SHA256())
            ),
        )
        witness_args=dict(
            org_id=org, target_id=target, attempt_sequence=seq,
            actor_id=submitter, cert_body=witness, cert_signature=wsig,
            pinned_witness_key_der=public(witness_signer),
            archive_ref=ref, exact_archive_bytes=doc,
            pinned_archive_bucket="independent-security-archive",
            live_veto=veto, veto_nonce=nonce,
            pinned_veto_key_der=public(veto_signer), now=now,
        )
        async with release_session(sessions, org) as s:
            assert await witness_committed_selection(s, **witness_args) == "WITNESSED"
        async with release_session(sessions, org) as s:
            assert await witness_committed_selection(s, **witness_args) == "WITNESSED"

        # Even a valid signed witness cannot publish an unenrolled SHADOW target.
        async with release_session(sessions, org) as s:
            with pytest.raises(ReleaseConflict, match="not qualified"):
                await publish_witnessed_selection(
                    s, org_id=org, target_id=target, attempt_sequence=seq,
                    actor_id=submitter, now=now,
                    witness=witness, witness_signature=wsig,
                    witness_ref=ref, exact_witness_bytes=doc,
                    witness_public_der=public(witness_signer),
                    security_veto=veto, veto_nonce=nonce,
                    veto_public_der=public(veto_signer),
                    origin_binding=OriginBinding(
                        kind="aegentra.independent.origin-binding.v1",
                        audience="aegentra-publication-authority",
                        incarnation=incarnation, org_id=org, target_id=target,
                        subject_sha256=subject.digest(), destination_host=subject.destination_host,
                        resource_path=subject.resource_path,
                        origin_bucket="controlled-origin",
                        origin_key="published/allowed/current",
                        origin_version_id="v42",
                        content_sha256=subject.content_sha256,
                        delivery_profile_sha256=subject.delivery_profile_sha256,
                        fixed_bundle_sha256=subject.fixed_bundle_sha256,
                        signer_key_id="independent-origin-verifier",
                        issued_at=now, expires_at=now + timedelta(minutes=2),
                    ),
                    origin_signature=b"bad", origin_verifier_public_der=public(origin_signer),
                    origin_key_id="independent-origin-verifier",
                    pinned_witness_bucket="independent-security-archive",
                )

        # Administrative fixture only; production activation must validate
        # independent two-custodian origin, keys, closure and reachability.
        async with admin.begin() as s:
            await s.execute(update(ReleaseTarget).where(
                ReleaseTarget.org_id == org, ReleaseTarget.id == target,
            ).values(
                mode="ENFORCED", origin_bucket="controlled-origin",
                origin_key_prefix="published/allowed/",
            ))
        binding = OriginBinding(
            kind="aegentra.independent.origin-binding.v1",
            audience="aegentra-publication-authority",
            incarnation=incarnation, org_id=org, target_id=target,
            subject_sha256=subject.digest(), destination_host=subject.destination_host,
            resource_path=subject.resource_path,
            origin_bucket="controlled-origin", origin_key="published/allowed/current",
            origin_version_id="source-exact-version",
            content_sha256=subject.content_sha256,
            delivery_profile_sha256=subject.delivery_profile_sha256,
            fixed_bundle_sha256=subject.fixed_bundle_sha256,
            signer_key_id="independent-origin-verifier",
            issued_at=now, expires_at=now + timedelta(minutes=2),
        )
        bsig = origin_signer.sign(origin_message(binding), ec.ECDSA(hashes.SHA256()))
        publish_args=dict(
            org_id=org, target_id=target, attempt_sequence=seq,
            actor_id=submitter, now=now,
            witness=witness, witness_signature=wsig, witness_ref=ref,
            exact_witness_bytes=doc, witness_public_der=public(witness_signer),
            security_veto=veto, veto_nonce=nonce, veto_public_der=public(veto_signer),
            origin_binding=binding, origin_signature=bsig,
            origin_verifier_public_der=public(origin_signer),
            origin_key_id="independent-origin-verifier",
            pinned_witness_bucket="independent-security-archive",
        )
        async with release_session(sessions, org) as s:
            draft = await publish_witnessed_selection(s, **publish_args)
            assert draft.published_revision == 1 and draft.state == "PENDING_SEAL"

        with pytest.raises(ReleaseConflict):
            async with release_session(sessions, org) as s:
                await publish_witnessed_selection(s, **publish_args)

        async with admin.connect() as s:
            publication = (await s.execute(select(ReleasePublication).where(
                ReleasePublication.org_id == org
            ))).one()
            target_row = (await s.execute(select(ReleaseTarget).where(
                ReleaseTarget.org_id == org, ReleaseTarget.id == target
            ))).one()
            assert publication.status == "PENDING_SEAL"
            assert publication.origin_version_id == "source-exact-version"
            assert target_row.published_revision == 1
            assert target_row.published_attempt_sequence == seq

        # A public revision alone remains unavailable: its receipt is unsealed.
        with pytest.raises(ReleaseConflict):
            async with release_session(sessions, org) as s:
                await read_primary_head(
                    s, org_id=org, target_id=target,
                    witness_bucket="independent-security-archive",
                    nonce="h" * 43, now=now,
                )

        signer = ec.generate_private_key(ec.SECP256R1())
        receipt = PublicationReceipt(
            kind="aegentra.release.publication-receipt.v1",
            audience="aegentra-primary-head-authority",
            incarnation=incarnation, org_id=org, target_id=target,
            published_revision=1, attempt_sequence=seq,
            witness_sha256=ref.object_sha256,
            representation_sha256=subject.content_sha256,
            delivery_profile_sha256=subject.delivery_profile_sha256,
            fixed_bundle_sha256=subject.fixed_bundle_sha256,
            origin_bucket=binding.origin_bucket, origin_key=binding.origin_key,
            origin_version_id=binding.origin_version_id,
            signer_key_id="private-receipt-authority",
            issued_at=now,
        )
        receipt_sig = signer.sign(
            publication_receipt_message(receipt), ec.ECDSA(hashes.SHA256())
        )
        receipt_raw = signed_publication_receipt_bytes(receipt, receipt_sig)
        receipt_ref = PublicationArchiveRef(
            bucket="independent-security-archive",
            key=(
                f"publications/v1/{org.hex}/{incarnation.hex}/"
                f"{target.hex}/{1:020d}"
            ),
            version_id="receipt-exact-version",
            sha256=hashlib.sha256(receipt_raw).hexdigest(),
        )
        seal_args = dict(
            org_id=org, target_id=target, published_revision=1,
            actor_id=submitter, body=receipt, signature_der=receipt_sig,
            public_key_der=public(signer),
            expected_signer_key_id="private-receipt-authority",
            archive_ref=receipt_ref, exact_archive_bytes=receipt_raw,
            enrolled_archive_bucket="independent-security-archive", now=now,
        )
        async with release_session(sessions, org) as s:
            assert await seal_publication_receipt(s, **seal_args) == "SEALED"
        async with release_session(sessions, org) as s:
            assert await seal_publication_receipt(s, **seal_args) == "SEALED"

        head_key = ec.generate_private_key(ec.SECP256R1())
        class FakeKMS:
            def sign(self, **kwargs):
                return {"Signature": head_key.sign(
                    kwargs["Message"], ec.ECDSA(hashes.SHA256())
                )}

        async with release_session(sessions, org) as s:
            head = await read_primary_head(
                s, org_id=org, target_id=target,
                witness_bucket="independent-security-archive",
                nonce="h" * 43, now=now,
            )
        signed = KmsHeadSigner(
            kms=FakeKMS(), key_id="authority-kms-head",
            public_der=public(head_key),
        ).sign(head)
        assert verify_head(
            signed, pinned_key_der=public(head_key),
            nonce="h" * 43, org_id=org, target_id=target,
            incarnation=incarnation, host=subject.destination_host,
            path=subject.resource_path, now=now,
        ).published_revision == 1

        # STOP denies future signed heads without altering historical receipts.
        from aegentra.release_state import set_target_guard
        async with release_session(sessions, org) as s:
            await set_target_guard(
                s, org_id=org, target_id=target,
                actor_id=submitter, new_guard="STOP_SERVING",
            )
        with pytest.raises(ReleaseConflict):
            async with release_session(sessions, org) as s:
                await read_primary_head(
                    s, org_id=org, target_id=target,
                    witness_bucket="independent-security-archive",
                    nonce="h" * 43, now=now,
                )
    finally:
        try:
            async with admin.begin() as s:
                await s.execute(delete(OutboxEvent).where(OutboxEvent.org_id == org))
                await s.execute(delete(AuditEntry).where(AuditEntry.org_id == org))
                await s.execute(delete(AuditStream).where(AuditStream.org_id == org))
                await s.execute(delete(ReleasePublication).where(ReleasePublication.org_id == org))
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
            await admin.dispose()
