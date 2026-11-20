from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from aegentra.origin_binding import OriginBinding, origin_message, verify_origin_binding
from aegentra.review_crypto import ReviewRejected, ReviewSubject


def fixture():
    now = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)
    subject = ReviewSubject(
        kind="aegentra.review.subject.v1",
        incarnation=uuid4(), org_id=uuid4(), asset_id=uuid4(), target_id=uuid4(),
        destination_host="origin.example.test", resource_path="/index.html", content_sha256="a" * 64,
        storage_sha256="b" * 64, independent_bytes_sha256="a" * 64,
        delivery_profile_sha256="c" * 64, policy_sha256="d" * 64,
        baseline_sha256="e" * 64, source_attestation_sha256="f" * 64,
        scan_receipt_sha256="1" * 64, change_request_sha256="2" * 64,
        baseline_revision=1, prior_published_revision=0,
        org_epoch=1, target_epoch=1, submitter_person_id=uuid4(),
    )
    key = ec.generate_private_key(ec.SECP256R1())
    pub = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    proof = OriginBinding(
        kind="aegentra.independent.origin-binding.v1",
        audience="aegentra-publication-authority",
        incarnation=subject.incarnation,
        org_id=subject.org_id, target_id=subject.target_id,
        subject_sha256=subject.digest(), destination_host=subject.destination_host,
        resource_path=subject.resource_path,
        origin_bucket="pinned-origin", origin_key="published/trusted/v1",
        origin_version_id="version-1", content_sha256=subject.content_sha256,
        delivery_profile_sha256=subject.delivery_profile_sha256,
        signer_key_id="independent-origin-verifier",
        issued_at=now, expires_at=now + timedelta(minutes=2),
    )
    sig = key.sign(origin_message(proof), ec.ECDSA(hashes.SHA256()))
    return subject, proof, sig, key, pub, now


def check(subject, proof, sig, pub, now):
    return verify_origin_binding(
        binding=proof, signature_der=sig,
        pinned_verifier_der=pub,
        expected_key_id="independent-origin-verifier",
        subject=subject, enrolled_bucket="pinned-origin",
        enrolled_key_prefix="published/trusted/", now=now,
    )


def test_exact_signed_origin_version_is_bound_to_subject():
    subject, proof, sig, key, pub, now = fixture()
    assert check(subject, proof, sig, pub, now) is None


@pytest.mark.parametrize("tamper", [
    "version", "prefix", "bucket", "key", "subject", "signature", "expired",
])
def test_origin_signatures_fail_closed(tamper):
    subject, proof, sig, key, pub, now = fixture()
    if tamper == "version":
        proof = proof.model_copy(update={"origin_version_id": "null"})
    elif tamper == "prefix":
        proof = proof.model_copy(update={"origin_key": "other/escape"})
    elif tamper == "bucket":
        proof = proof.model_copy(update={"origin_bucket": "other"})
    elif tamper == "key":
        pub = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    elif tamper == "subject":
        subject = subject.model_copy(update={"policy_sha256": "9" * 64})
    elif tamper == "signature":
        sig = key.sign(b"wrong-context", ec.ECDSA(hashes.SHA256()))
    else:
        now += timedelta(minutes=10)
    with pytest.raises(ReviewRejected):
        check(subject, proof, sig, pub, now)
