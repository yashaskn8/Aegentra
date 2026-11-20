"""Immutable publication receipt archive with conditional S3 version create."""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any

from aegentra.publication_receipt import (
    PublicationReceipt, signed_publication_receipt_bytes,
)

MAX_PUBLICATION_RECEIPT = 32 * 1024


class PublicationArchiveError(ValueError):
    pass


@dataclass(frozen=True)
class PublicationArchiveRef:
    bucket: str
    key: str
    version_id: str
    sha256: str


@dataclass(frozen=True)
class PublicationArchive:
    s3: Any
    sts: Any
    bucket: str
    expected_account_id: str

    def _check_custody(self) -> None:
        if (
            len(self.expected_account_id) != 12
            or not self.expected_account_id.isdecimal()
            or self.sts.get_caller_identity().get("Account") != self.expected_account_id
        ):
            raise PublicationArchiveError("archive writer account not enrolled")

    @staticmethod
    def key_for(body: PublicationReceipt) -> str:
        return (
            f"publications/v1/{body.org_id.hex}/{body.incarnation.hex}/"
            f"{body.target_id.hex}/{body.published_revision:020d}"
        )

    def append(self, body: PublicationReceipt, signature_der: bytes) -> PublicationArchiveRef:
        self._check_custody()
        raw = signed_publication_receipt_bytes(body, signature_der)
        if len(raw) > MAX_PUBLICATION_RECEIPT:
            raise PublicationArchiveError("receipt exceeds 32 KiB")
        checksum = hashlib.sha256(raw).digest()
        response = self.s3.put_object(
            Bucket=self.bucket, Key=self.key_for(body), Body=raw,
            ContentType="application/json",
            ChecksumSHA256=base64.b64encode(checksum).decode("ascii"),
            IfNoneMatch="*",
        )
        version = response.get("VersionId")
        if not isinstance(version, str) or not version or version == "null":
            raise PublicationArchiveError("S3 did not return a locked version")
        return PublicationArchiveRef(
            bucket=self.bucket, key=self.key_for(body),
            version_id=version, sha256=checksum.hex(),
        )

    def read_exact(self, ref: PublicationArchiveRef) -> bytes:
        self._check_custody()
        if (
            ref.bucket != self.bucket
            or not ref.key.startswith("publications/v1/")
            or not ref.version_id or ref.version_id == "null"
        ):
            raise PublicationArchiveError("untrusted receipt reference")
        response = self.s3.get_object(
            Bucket=ref.bucket, Key=ref.key, VersionId=ref.version_id
        )
        if response.get("VersionId") != ref.version_id:
            raise PublicationArchiveError("S3 returned a different receipt version")
        length = response.get("ContentLength")
        if not isinstance(length, int) or not 0 < length <= MAX_PUBLICATION_RECEIPT:
            raise PublicationArchiveError("unbounded archive receipt")
        body = response.get("Body")
        if body is None:
            raise PublicationArchiveError("missing receipt bytes")
        try:
            raw = body.read(MAX_PUBLICATION_RECEIPT + 1)
        finally:
            body.close()
        if (
            not isinstance(raw, bytes) or len(raw) != length
            or hashlib.sha256(raw).hexdigest() != ref.sha256
        ):
            raise PublicationArchiveError("receipt bytes changed")
        return raw
