"""Isolated response lifecycle tests; no AWS calls or external data."""
import hashlib
import io

import pytest
from botocore.response import StreamingBody

from aegentra.evidence_verifier import EvidenceMismatch, verify_versioned_blob
from aegentra.intake import MAX_PART_BYTES
from aegentra.s3_reader import S3VersionReader


class LocalStorage:
    def __init__(self, body, *, version="v1", length=3):
        self.response = {"Body": body, "VersionId": version, "ContentLength": length}
        self.calls = []

    def get_object(self, **kwargs):
        self.calls.append(kwargs)
        return self.response


def reader_for(storage):
    return S3VersionReader(client=storage, bucket="fixture-bucket", key="fixture/part")


@pytest.mark.parametrize("version,length", [
    ("v2", 3), ("v1", None), ("v1", 0), ("v1", MAX_PART_BYTES + 1),
    ("v1", True),
])
def test_invalid_metadata_closes_response_without_reading(version, length):
    raw = io.BytesIO(b"abc")
    storage = LocalStorage(StreamingBody(raw, 3), version=version, length=length)
    with pytest.raises(EvidenceMismatch):
        list(reader_for(storage).chunks("v1"))
    assert raw.closed
    assert storage.calls == [{"Bucket": "fixture-bucket", "Key": "fixture/part", "VersionId": "v1"}]


class RetainedIteratorReader:
    def __init__(self, reader):
        self.reader = reader
        self.iterator = None

    def chunks(self, version_id):
        self.iterator = self.reader.chunks(version_id)
        return self.iterator


def test_early_size_rejection_closes_retained_iterator():
    raw = io.BytesIO(b"abc")
    reader = RetainedIteratorReader(reader_for(LocalStorage(StreamingBody(raw, 3))))
    try:
        with pytest.raises(EvidenceMismatch, match="oversized blob"):
            verify_versioned_blob(reader=reader, version_id="v1",
                                  expected_sha256=hashlib.sha256(b"a").hexdigest(), expected_length=1)
        assert raw.closed
    finally:
        reader.iterator.close()


@pytest.mark.parametrize("digest_ok", [True, False])
def test_complete_read_closes_response(digest_ok):
    raw = io.BytesIO(b"abc")
    reader = reader_for(LocalStorage(StreamingBody(raw, 3)))
    kwargs = dict(reader=reader, version_id="v1", expected_length=3,
                  expected_sha256=hashlib.sha256(b"abc" if digest_ok else b"xyz").hexdigest())
    if digest_ok:
        assert verify_versioned_blob(**kwargs).byte_length == 3
    else:
        with pytest.raises(EvidenceMismatch, match="digest mismatch"):
            verify_versioned_blob(**kwargs)
    assert raw.closed


def test_read_failure_closes_response():
    class BrokenStream(io.BytesIO):
        def read(self, size=-1):
            raise OSError("fixture read failure")

    raw = BrokenStream(b"abc")
    reader = reader_for(LocalStorage(StreamingBody(raw, 3)))
    with pytest.raises(OSError, match="fixture read failure"):
        list(reader.chunks("v1"))
    assert raw.closed


def test_plain_iterable_reader_remains_supported():
    class PlainReader:
        def chunks(self, version_id):
            return [b"a", b"bc"]

    result = verify_versioned_blob(reader=PlainReader(), version_id="v1",
                                  expected_sha256=hashlib.sha256(b"abc").hexdigest(), expected_length=3)
    assert result.byte_length == 3
