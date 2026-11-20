from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegentra.review_crypto import ReviewRejected, ReviewSubject
from aegentra.staging_proof import (
    StagingProof, stage_message, verify_staging_proof,
)


def fixture():
    from uuid import uuid4
    now = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
    subject = ReviewSubject(
        kind="aegentra.review.subject.v1",
        incarnation=uuid4(), org_id=uuid4(), asset_id=uuid4(),
        target_id=uuid4(), destination_host="example.test", resource_path="/index.html",
        content_sha256="1" * 64, storage_sha256="2" * 64,
        independent_bytes_sha256="1" * 64,
        delivery_profile_sha256="3" * 64,
        policy_sha256="4" * 64, baseline_sha256="5" * 64,
        source_attestation_sha256="6" * 64, scan_receipt_sha256="7" * 64,
        change_request_sha256="8" * 64, baseline_revision=1,
        prior_published_revision=0, org_epoch=1, target_epoch=1,
        submitter_person_id=uuid4(),
    )
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    proof = StagingProof(
        kind="aegentra.release.staging-proof.v1",
        audience="aegentra-authority-redeem",
        incarnation=subject.incarnation, org_id=subject.org_id,
        target_id=subject.target_id, subject_sha256=subject.digest(),
        content_sha256=subject.content_sha256,
        storage_sha256=subject.storage_sha256,
        delivery_profile_sha256=subject.delivery_profile_sha256,
        prior_published_revision=0, verifier_key_id="other-trust-root",
        issued_at=now, expires_at=now + timedelta(seconds=60),
    )
    signature = private.sign(stage_message(proof))
    return subject, proof, private, public, signature, now


def check(subject, proof, public, signature, now):
    return verify_staging_proof(
        subject=subject, proof=proof, signature=signature,
        public_key=public, expected_key_id="other-trust-root", now=now,
    )


def test_valid_verifier_proof_binds_staged_approved_bytes():
    subject, proof, private, public, signature, now = fixture()
    assert len(check(subject, proof, public, signature, now)) == 64


@pytest.mark.parametrize("change", ["bytes", "subject", "key", "expired", "signature", "audience"])
def test_wrong_or_replayed_staging_evidence_denied(change):
    subject, proof, private, public, signature, now = fixture()
    if change == "bytes":
        proof = proof.model_copy(update={"content_sha256": "f" * 64})
    if change == "subject":
        subject = subject.model_copy(update={"policy_sha256": "a" * 64})
    if change == "key":
        public = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    if change == "expired":
        now += timedelta(minutes=2)
    if change == "signature":
        signature = private.sign(b"wrong signing domain")
    if change == "audience":
        proof = proof.model_copy(update={"audience": "other"})
    with pytest.raises((ReviewRejected, ValueError)):
        check(subject, proof, public, signature, now)
