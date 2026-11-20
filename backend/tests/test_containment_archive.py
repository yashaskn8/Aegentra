"""Independent S3 containment archive requires conditional versions and exact bytes."""
import io
from uuid import uuid4

import pytest

from aegentra.containment_archive import (
    ContainmentArchiveError, ContainmentProofArchive,
)


class FakeSTS:
    account = "123456789012"

    def get_caller_identity(self):
        return {"Account": self.account}


class FakeS3:
    def __init__(self):
        self.items = {}
        self.puts = []
        self.gets = []
        self.version = "fixed-original-v1"

    def put_object(self, **kwargs):
        self.puts.append(kwargs)
        if kwargs["Key"] in self.items:
            raise RuntimeError("S3 PreconditionFailed")
        self.items[kwargs["Key"]] = bytes(kwargs["Body"])
        return {"VersionId": self.version}

    def get_object(self, **kwargs):
        self.gets.append(kwargs)
        body = self.items[kwargs["Key"]]
        return {
            "VersionId": self.version,
            "ContentLength": len(body),
            "Body": io.BytesIO(body),
        }


def fixture():
    s3, sts, org, case = FakeS3(), FakeSTS(), uuid4(), uuid4()
    service = ContainmentProofArchive(
        s3=s3, sts=sts, bucket="independent-incidents",
        security_account_id="123456789012",
    )
    return service, s3, sts, org, case


def test_conditional_append_and_exact_version_read():
    service, s3, sts, org, case = fixture()
    payload = b'{"kind":"aegentra.incident.containment-proof.v1"}'
    ref = service.append(
        org_id=org, case_id=case, generation=4,
        canonical_proof=payload,
    )
    assert ref.version_id == "fixed-original-v1"
    assert s3.puts[0]["IfNoneMatch"] == "*"
    assert ref.key.endswith("/00000000000000000004")
    assert service.read_exact(ref, org_id=org, case_id=case, generation=4) == payload
    assert s3.gets[0]["VersionId"] == "fixed-original-v1"
    with pytest.raises(RuntimeError):
        service.append(
            org_id=org, case_id=case, generation=4,
            canonical_proof=payload,
        )


@pytest.mark.parametrize("change", [
    "account", "key", "bucket", "version", "digest", "bytes", "wrong_generation",
])
def test_wrong_source_or_modified_proof_is_rejected(change):
    service, s3, sts, org, case = fixture()
    ref = service.append(
        org_id=org, case_id=case, generation=4,
        canonical_proof=b'{"verified":true}',
    )
    if change == "account":
        sts.account = "000000000000"
    elif change == "key":
        ref = ref.__class__(ref.bucket, "elsewhere", ref.version_id, ref.sha256)
    elif change == "bucket":
        ref = ref.__class__("other", ref.key, ref.version_id, ref.sha256)
    elif change == "version":
        ref = ref.__class__(ref.bucket, ref.key, "null", ref.sha256)
    elif change == "digest":
        ref = ref.__class__(ref.bucket, ref.key, ref.version_id, "f" * 64)
    elif change == "bytes":
        s3.items[ref.key] += b"junk"
    else:
        ref = ref.__class__(
            ref.bucket, service.key_for(
                org_id=org, case_id=case, generation=5,
            ), ref.version_id, ref.sha256,
        )
    with pytest.raises(ContainmentArchiveError):
        service.read_exact(ref, org_id=org, case_id=case, generation=4)


def test_lost_version_or_excessive_proof_is_not_accepted():
    service, s3, sts, org, case = fixture()
    s3.version = "null"
    with pytest.raises(ContainmentArchiveError):
        service.append(
            org_id=org, case_id=case, generation=1,
            canonical_proof=b'{"proof":1}',
        )
    with pytest.raises(ContainmentArchiveError):
        service.append(
            org_id=org, case_id=case, generation=2,
            canonical_proof=b"x" * (64 * 1024 + 1),
        )
