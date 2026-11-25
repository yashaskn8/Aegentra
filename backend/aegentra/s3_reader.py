"""Read a pinned S3 VersionId with no implicit "latest" fallback.

Use only in a separately authorized native evidence verifier. S3 permissions
must restrict this reader to the expected bucket and server-issued key prefix.
"""
from __future__ import annotations

from collections.abc import Iterable

from aegentra.evidence_verifier import EvidenceMismatch
from aegentra.intake import MAX_PART_BYTES


class S3VersionReader:
    def __init__(self, *, client: object, bucket: str, key: str) -> None:
        if not bucket or not key or key.startswith("/") or ".." in key.split("/"):
            raise ValueError("bucket/key must come from a validated server ticket")
        self.client = client
        self.bucket = bucket
        self.key = key

    def chunks(self, version_id: str) -> Iterable[bytes]:
        if (
            not isinstance(version_id, str)
            or version_id in ("", "null")
            or len(version_id) > 256
        ):
            raise EvidenceMismatch("a non-null pinned S3 version is required")
        # Injected client implements boto3 S3 get_object. Never permit a
        # client-selected bucket or unversioned GET.
        response = self.client.get_object(
            Bucket=self.bucket, Key=self.key, VersionId=version_id
        )
        body = response.get("Body")
        try:
            if response.get("VersionId") != version_id:
                raise EvidenceMismatch("S3 returned an unexpected object version")
            declared_length = response.get("ContentLength")
            if type(declared_length) is not int or not 0 < declared_length <= MAX_PART_BYTES:
                raise EvidenceMismatch("S3 response length unavailable or excessive")
            if body is None:
                raise EvidenceMismatch("missing S3 body")
            yield from body.iter_chunks(chunk_size=64 * 1024)
        finally:
            if body is not None:
                body.close()
