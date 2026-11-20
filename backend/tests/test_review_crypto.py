from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegentra.review_crypto import (
    EndorsementBody, ReviewRejected, ReviewerCredential,
    ReviewSubject, SignedEndorsement, endorsement_message, verify_approval_set,
)


def fixture():
    now = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)
    one, two, submitter = uuid4(), uuid4(), uuid4()
    subject = ReviewSubject(
        kind="aegentra.review.subject.v1",
        incarnation=uuid4(), org_id=uuid4(), asset_id=uuid4(),
        target_id=uuid4(), destination_host="origin.example.test", resource_path="/index.html",
        content_sha256="a" * 64, storage_sha256="b" * 64,
        independent_bytes_sha256="a" * 64, delivery_profile_sha256="c" * 64,
        policy_sha256="d" * 64, baseline_sha256="e" * 64,
        source_attestation_sha256="f" * 64,
        scan_receipt_sha256="1" * 64, change_request_sha256="2" * 64,
        baseline_revision=1, prior_published_revision=0,
        org_epoch=1, target_epoch=1, submitter_person_id=submitter,
    )
    privates = [Ed25519PrivateKey.generate() for _ in range(2)]
    credentials = [
        ReviewerCredential(
            person_id=person, key_id=f"key-{i}", custody_group=f"group-{i}",
            enrollment_generation=4,
            public_ed25519=key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
            independently_verified=True,
        )
        for i, (person, key) in enumerate(zip((one, two), privates), start=1)
    ]
    bodies = [
        EndorsementBody(
            kind="aegentra.review.endorsement.v1",
            subject_sha256=subject.digest(), person_id=credential.person_id,
            key_id=credential.key_id, custody_group=credential.custody_group,
            challenge_nonce=("n" if i == 1 else "m") * 43,
            enrollment_generation=4, audience="aegentra-independent-review",
            action="ENDORSE_FINAL_BYTES", issued_at=now - timedelta(seconds=5),
            expires_at=now + timedelta(seconds=90),
        )
        for i, credential in enumerate(credentials, start=1)
    ]
    endorsements = tuple(
        SignedEndorsement(body, key.sign(endorsement_message(body)))
        for body, key in zip(bodies, privates)
    )
    return subject, endorsements, {v.key_id: v for v in credentials}, now, privates


def check(subject, endorsements, enrolled, now, challenges=frozenset()):
    return verify_approval_set(
        subject=subject, endorsements=endorsements,
        enrolled=enrolled, used_challenges=challenges, now=now,
    )


def test_two_human_signatures_are_deterministic_and_non_authorizing():
    subject, endorsements, enrolled, now, _ = fixture()
    one = check(subject, endorsements, enrolled, now)
    two = check(subject, endorsements[::-1], enrolled, now)
    assert one == two
    assert one.subject_sha256 == subject.digest()
    assert len(set(one.people)) == len(set(one.groups)) == 2
    assert one.approval_set_sha256 != subject.digest()


@pytest.mark.parametrize("tamper", [
    "self", "group", "key", "nonce", "replayed", "signature", "subject",
    "enrollment", "inactive", "expired", "fake_hardware", "wrong_purpose",
])
def test_all_untrusted_reviewer_cases_fail(tamper: str):
    subject, signed, registry, now, keys = fixture()
    a, b = signed
    replayed = frozenset()
    if tamper == "self":
        subject = subject.model_copy(update={"submitter_person_id": a.body.person_id})
    elif tamper == "group":
        b = SignedEndorsement(
            b.body.model_copy(update={"custody_group": a.body.custody_group}), b.signature
        )
    elif tamper == "key":
        b = SignedEndorsement(b.body.model_copy(update={"key_id": a.body.key_id}), b.signature)
    elif tamper == "nonce":
        b = SignedEndorsement(
            b.body.model_copy(update={"challenge_nonce": a.body.challenge_nonce}), b.signature
        )
    elif tamper == "replayed":
        replayed = frozenset({b.body.challenge_nonce})
    elif tamper == "signature":
        b = SignedEndorsement(b.body, b"x" * 64)
    elif tamper == "subject":
        subject = subject.model_copy(update={"policy_sha256": "9" * 64})
    elif tamper == "enrollment":
        registry[b.body.key_id] = replace(registry[b.body.key_id], enrollment_generation=5)
    elif tamper == "inactive":
        registry[b.body.key_id] = replace(registry[b.body.key_id], active=False)
    elif tamper == "expired":
        now += timedelta(minutes=3)
    elif tamper == "fake_hardware":
        registry[b.body.key_id] = replace(registry[b.body.key_id], independently_verified=False)
    elif tamper == "wrong_purpose":
        b = SignedEndorsement(
            b.body.model_copy(update={"action": "OTHER_ACTION"}), b.signature
        )
    with pytest.raises((ReviewRejected, ValueError)):
        check(subject, (a, b), registry, now, replayed)


def test_cannot_use_grant_or_witness_signature_as_endorsement():
    subject, signed, registry, now, keys = fixture()
    forged = SignedEndorsement(
        signed[0].body,
        keys[0].sign(b"aegentra.release.grant.v1\x00" + signed[0].body.canonical()),
    )
    with pytest.raises(ReviewRejected):
        check(subject, (forged, signed[1]), registry, now)


def test_independent_final_byte_mismatch_denies_subject():
    subject, _, _, _, _ = fixture()
    with pytest.raises(ValueError, match="independent"):
        ReviewSubject.model_validate({
            **subject.model_dump(mode="json"),
            "independent_bytes_sha256": "8" * 64,
        })
