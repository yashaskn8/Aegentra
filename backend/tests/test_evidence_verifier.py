import hashlib

import pytest

from aegentra.evidence_verifier import EvidenceMismatch, verify_versioned_blob
from aegentra.s3_reader import S3VersionReader


class FakeReader:
    def __init__(self, parts: list[bytes]) -> None:
        self.parts = parts
        self.requested = None

    def chunks(self, version_id: str):
        self.requested = version_id
        yield from self.parts


def test_verified_original_bytes() -> None:
    value = b"evidence-data"
    reader = FakeReader([value[:3], value[3:]])
    sealed = verify_versioned_blob(
        reader=reader, version_id="version-1",
        expected_sha256=hashlib.sha256(value).hexdigest(),
        expected_length=len(value),
    )
    assert reader.requested == "version-1"
    assert sealed.sha256 == hashlib.sha256(value).hexdigest()
    assert sealed.byte_length == len(value)


@pytest.mark.parametrize("data,expected_length", [
    ([b"abc"], 4),
    ([b"abc", b"d"], 3),
    ([b"wrong"], 5),
])
def test_reject_length_or_digest_mismatch(data: list[bytes], expected_length: int) -> None:
    with pytest.raises(EvidenceMismatch):
        verify_versioned_blob(
            reader=FakeReader(data), version_id="version-1",
            expected_sha256=hashlib.sha256(b"other").hexdigest(),
            expected_length=expected_length,
        )


def test_no_missing_version() -> None:
    with pytest.raises(EvidenceMismatch):
        verify_versioned_blob(
            reader=FakeReader([b"a"]), version_id="",
            expected_sha256=hashlib.sha256(b"a").hexdigest(), expected_length=1,
        )


def test_s3_reader_does_not_fall_back_to_latest_object() -> None:
    class FakeS3:
        def get_object(self, **kwargs):
            assert kwargs == {
                "Bucket": "trusted-bucket", "Key": "org/staging/p1",
                "VersionId": "pinned-v1",
            }
            return {"VersionId": "latest-v2", "ContentLength": 1, "Body": None}

    reader = S3VersionReader(client=FakeS3(), bucket="trusted-bucket",
                             key="org/staging/p1")
    with pytest.raises(EvidenceMismatch, match="unexpected object version"):
        list(reader.chunks("pinned-v1"))


def test_reader_rejects_ambiguous_key() -> None:
    with pytest.raises(ValueError):
        S3VersionReader(client=object(), bucket="bucket", key="../escape")


@pytest.mark.parametrize("version_id", [None, "", "null", b"v1", "x" * 257])
def test_s3_reader_refuses_unpinned_or_invalid_version_before_network(version_id):
    class RefuseNetwork:
        def get_object(self, **kwargs):
            pytest.fail("storage must not be contacted for unpinned versions")

    reader = S3VersionReader(
        client=RefuseNetwork(), bucket="trusted-bucket", key="org/staging/p1",
    )
    with pytest.raises(EvidenceMismatch, match="non-null pinned"):
        list(reader.chunks(version_id))


@pytest.mark.parametrize("version_id", [None, "", "null", b"v1", "x" * 257])
def test_byte_verifier_rejects_unpinned_version_without_reading(version_id):
    reader = FakeReader([b"test"])
    with pytest.raises(EvidenceMismatch, match="storage version"):
        verify_versioned_blob(
            reader=reader, version_id=version_id,
            expected_sha256=hashlib.sha256(b"test").hexdigest(),
            expected_length=4,
        )
    assert reader.requested is None


@pytest.mark.parametrize("bad_length", [True, 0, -1, "4"])
def test_byte_verifier_requires_integer_length(bad_length):
    with pytest.raises(EvidenceMismatch, match="expected length"):
        verify_versioned_blob(
            reader=FakeReader([b"test"]), version_id="version-1",
            expected_sha256=hashlib.sha256(b"test").hexdigest(),
            expected_length=bad_length,
        )
