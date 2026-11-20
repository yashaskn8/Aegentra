import hashlib
import io
from uuid import uuid4
from datetime import datetime, timedelta, timezone

import pytest

from aegentra.witness_archive import (
    ConditionalWitnessArchive, WitnessArchiveError,
)
from aegentra.witness_crypto import WitnessBody, WitnessArchiveRef


class STS:
    def __init__(self, account="123456789012"):
        self.account = account
    def get_caller_identity(self):
        return {"Account": self.account}


class S3:
    def __init__(self):
        self.items = {}
        self.last_put = None
        self.last_get = None

    def put_object(self, **kw):
        self.last_put = kw
        key = kw["Key"]
        if key in self.items:
            raise RuntimeError("S3 PreconditionFailed: key already exists")
        self.items[key] = bytes(kw["Body"])
        return {"VersionId": "real-immutable-v1"}

    def get_object(self, **kw):
        self.last_get = kw
        data = self.items[kw["Key"]]
        return {
            "VersionId": kw["VersionId"],
            "ContentLength": len(data),
            "Body": io.BytesIO(data),
        }


def body():
    now = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)
    return WitnessBody(
        kind="aegentra.security.witness.v1",
        audience="aegentra-release-publication",
        incarnation=uuid4(), org_id=uuid4(), target_id=uuid4(),
        attempt_sequence=1, prior_published_revision=0,
        predecessor_witness_sha256="0" * 64,
        subject_sha256="1" * 64, approval_set_sha256="2" * 64,
        staging_sha256="3" * 64, content_sha256="4" * 64,
        delivery_profile_sha256="5" * 64,
        security_root_generation=1,
        selection_deadline=now + timedelta(seconds=50), issued_at=now,
    )


def test_conditional_create_and_version_locked_read():
    s3 = S3()
    archive = ConditionalWitnessArchive(
        s3=s3, sts=STS(), bucket="independent-archive",
        security_account_id="123456789012",
    )
    doc = body()
    ref = archive.conditional_create(doc, b"f" * 64)
    assert ref.version_id == "real-immutable-v1"
    assert s3.last_put["IfNoneMatch"] == "*"
    assert s3.last_put["Bucket"] == "independent-archive"
    assert archive.read_exact_version(ref) == s3.items[ref.key]
    assert s3.last_get == {
        "Bucket": ref.bucket, "Key": ref.key, "VersionId": "real-immutable-v1"
    }
    with pytest.raises(RuntimeError):
        archive.conditional_create(doc, b"f" * 64)


@pytest.mark.parametrize("tamper", ["account", "bucket", "hash", "version", "bytes"])
def test_archive_fail_closed_on_wrong_identity_or_bytes(tamper):
    s3 = S3()
    sts = STS()
    archive = ConditionalWitnessArchive(
        s3=s3, sts=sts, bucket="independent-archive",
        security_account_id="123456789012",
    )
    ref = archive.conditional_create(body(), b"f" * 64)
    if tamper == "account":
        sts.account = "000000000000"
    elif tamper == "bucket":
        ref = WitnessArchiveRef("other", ref.key, ref.version_id, ref.object_sha256)
    elif tamper == "hash":
        ref = WitnessArchiveRef(ref.bucket, ref.key, ref.version_id, "a" * 64)
    elif tamper == "version":
        ref = WitnessArchiveRef(ref.bucket, ref.key, "null", ref.object_sha256)
    else:
        s3.items[ref.key] += b"x"
    with pytest.raises(WitnessArchiveError):
        archive.read_exact_version(ref)


def test_missing_version_from_s3_is_rejected():
    s3 = S3()
    s3.put_object = lambda **kwargs: {}
    archive = ConditionalWitnessArchive(
        s3=s3, sts=STS(), bucket="independent-archive",
        security_account_id="123456789012",
    )
    with pytest.raises(WitnessArchiveError, match="version"):
        archive.conditional_create(body(), b"f" * 64)
