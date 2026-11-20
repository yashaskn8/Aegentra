"""Domain-separated publication receipts and immutable exact S3 archive."""
from datetime import datetime, timedelta, timezone
import io
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from aegentra.db import ReleasePublication
from aegentra.publication_archive import (
    PublicationArchive, PublicationArchiveError,
)
from aegentra.publication_receipt import (
    PublicationReceipt, publication_receipt_message,
    signed_publication_receipt_bytes, verify_publication_receipt,
)
from aegentra.review_crypto import ReviewRejected


def fixture():
    now = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)
    org, target, incarnation = uuid4(), uuid4(), uuid4()
    publication = ReleasePublication(
        org_id=org, target_id=target,
        published_revision=1, attempt_sequence=3,
        witness_version_id="witness-version",
        witness_sha256=b"w" * 32, representation_sha256=b"b" * 32,
        delivery_profile_sha256=b"p" * 32, created_at=now,
        origin_bucket="trusted-origin",
        origin_key="published/key", origin_version_id="source-v1",
        status="PENDING_SEAL",
    )
    receipt = PublicationReceipt(
        kind="aegentra.release.publication-receipt.v1",
        audience="aegentra-primary-head-authority",
        org_id=org, target_id=target, incarnation=incarnation,
        published_revision=1, attempt_sequence=3,
        witness_sha256=publication.witness_sha256.hex(),
        representation_sha256=publication.representation_sha256.hex(),
        delivery_profile_sha256=publication.delivery_profile_sha256.hex(),
        origin_bucket="trusted-origin", origin_key="published/key",
        origin_version_id="source-v1",
        signer_key_id="publication-authority-key",
        issued_at=now,
    )
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sig = private.sign(publication_receipt_message(receipt), ec.ECDSA(hashes.SHA256()))
    return publication, receipt, incarnation, now, public, sig


def check(pub, receipt, inc, now, public, sig):
    return verify_publication_receipt(
        body=receipt, signature_der=sig,
        pinned_public_der=public, expected_key_id="publication-authority-key",
        publication=pub, incarnation=inc, now=now,
    )


def test_receipt_signature_binds_current_publication():
    pub, receipt, inc, now, public, sig = fixture()
    assert len(check(pub, receipt, inc, now, public, sig)) == 64


@pytest.mark.parametrize("mutation", ["witness", "origin_version", "revision", "signature", "key"])
def test_receipt_for_other_publication_cannot_be_sealed(mutation):
    pub, receipt, inc, now, public, sig = fixture()
    if mutation == "witness":
        pub.witness_sha256 = b"x" * 32
    elif mutation == "origin_version":
        pub.origin_version_id = "other-version"
    elif mutation == "revision":
        pub.published_revision = 2
    elif mutation == "signature":
        sig = b"t" * 40
    else:
        public = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    with pytest.raises(ReviewRejected):
        check(pub, receipt, inc, now, public, sig)


class FakeSTS:
    def get_caller_identity(self):
        return {"Account": "123456789012"}


class FakeS3:
    def __init__(self):
        self.objects = {}
        self.writes = []

    def put_object(self, **kwargs):
        self.writes.append(kwargs)
        if kwargs["Key"] in self.objects:
            raise RuntimeError("conditional create precondition failed")
        self.objects[kwargs["Key"]] = bytes(kwargs["Body"])
        return {"VersionId": "locked-123"}

    def get_object(self, **kwargs):
        data = self.objects[kwargs["Key"]]
        return {
            "VersionId": kwargs["VersionId"],
            "ContentLength": len(data),
            "Body": io.BytesIO(data),
        }


def test_conditional_publication_archive_exact_version():
    pub, receipt, inc, now, public, sig = fixture()
    s3 = FakeS3()
    archive = PublicationArchive(
        s3=s3, sts=FakeSTS(), bucket="security-account-archive",
        expected_account_id="123456789012",
    )
    ref = archive.append(receipt, sig)
    assert ref.version_id == "locked-123"
    assert s3.writes[0]["IfNoneMatch"] == "*"
    assert archive.read_exact(ref) == signed_publication_receipt_bytes(receipt, sig)
    with pytest.raises(RuntimeError):
        archive.append(receipt, sig)


def test_archive_version_mismatch_is_rejected():
    pub, receipt, inc, now, public, sig = fixture()
    s3 = FakeS3()
    archive = PublicationArchive(
        s3=s3, sts=FakeSTS(), bucket="security-account-archive",
        expected_account_id="123456789012",
    )
    ref = archive.append(receipt, sig)
    corrupted = ref.__class__(ref.bucket, ref.key, ref.version_id, "0" * 64)
    with pytest.raises(PublicationArchiveError):
        archive.read_exact(corrupted)
