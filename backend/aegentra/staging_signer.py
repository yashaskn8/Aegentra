"""Short-lived S3 staging PUT signing, never final-vault authority.

The signer must have *only* staging-prefix write permission. A signature
is NOT independent evidence: S3 VersionId and original bytes require separate
trusted verification after finalization.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Protocol



class PresignedClient(Protocol):
    def generate_presigned_url(
        self, ClientMethod: str, Params: dict, ExpiresIn: int,
        HttpMethod: str,
    ) -> str: ...


@dataclass(frozen=True)
class UploadPut:
    url: str
    headers: dict[str, str]
    expires_seconds: int


class StagingSigner:
    def __init__(self, *, client: PresignedClient, bucket: str):
        if not bucket or "/" in bucket or len(bucket) > 63:
            raise ValueError("staging bucket must be a configured bucket name")
        self.client, self.bucket = client, bucket

    def issue(self, *, key: str, sha256: str, media_type: str,
              byte_length: int) -> UploadPut:
        if not key.startswith("staging/") or not 0 < byte_length <= 10 * 1024 * 1024:
            raise ValueError("invalid staging request")
        checksum = base64.b64encode(bytes.fromhex(sha256)).decode("ascii")
        length = str(byte_length)
        headers = {
            "Content-Type": media_type,
            "Content-Length": length,
            "x-amz-checksum-sha256": checksum,
        }
        url = self.client.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": self.bucket, "Key": key,
                "ContentType": media_type,
                "ContentLength": byte_length,
                "ChecksumSHA256": checksum,
            },
            ExpiresIn=300,
            HttpMethod="PUT",
        )
        if not isinstance(url, str) or not url.startswith("https://"):
            raise ValueError("presigning failed")
        return UploadPut(url=url, headers=headers, expires_seconds=300)
