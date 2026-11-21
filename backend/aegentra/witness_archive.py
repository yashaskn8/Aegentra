"""Security-account S3 conditional witness archive; no mutable latest reads.

Supply a client with separate witness credentials. This module neither grants
those credentials nor proves compliance retention. The S3 bucket must have
versioning, Object Lock, strong key policy and independently administered IAM.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any

from aegentra.witness_crypto import (
    WitnessArchiveRef, WitnessBody, signed_certificate_bytes,
)

MAX_WITNESS = 64 * 1024


class WitnessArchiveError(ValueError):
    pass


@dataclass(frozen=True)
class ConditionalWitnessArchive:
    s3: Any
    sts: Any
    bucket: str
    security_account_id: str

    def _require_account(self) -> None:
        if (
            len(self.security_account_id) != 12
            or not self.security_account_id.isdecimal()
            or self.sts.get_caller_identity().get("Account") != self.security_account_id
        ):
            raise WitnessArchiveError("not operating in pinned security account")

    @staticmethod
    def certificate_key(body: WitnessBody) -> str:
        return (
            f"certificates/v1/{body.org_id.hex}/{body.incarnation.hex}/"
            f"{body.target_id.hex}/{body.attempt_sequence:020d}"
        )

    def conditional_create(
        self, body: WitnessBody, signature_der: bytes
    ) -> WitnessArchiveRef:
        """Write one versioned immutable object with If-None-Match '*'."""
        self._require_account()
        payload = signed_certificate_bytes(body, signature_der)
        if len(payload) > MAX_WITNESS:
            raise WitnessArchiveError("certificate exceeds limit")
        digest = hashlib.sha256(payload).hexdigest()
        key = self.certificate_key(body)
        response = self.s3.put_object(
            Bucket=self.bucket, Key=key, Body=payload,
            ContentType="application/json",
            ChecksumSHA256=base64.b64encode(
                hashlib.sha256(payload).digest()
            ).decode("ascii"),
            IfNoneMatch="*",
        )
        version = response.get("VersionId")
        if not isinstance(version, str) or not version or version == "null":
            raise WitnessArchiveError("S3 did not return an immutable object version")
        return WitnessArchiveRef(
            bucket=self.bucket, key=key, version_id=version,
            object_sha256=digest,
        )

    def read_exact_version(self, ref: WitnessArchiveRef) -> bytes:
        """Never fetch 'latest'; require exact version AND exact original bytes."""
        self._require_account()
        if (
            ref.bucket != self.bucket or not ref.version_id
            or ref.version_id == "null" or not ref.key.startswith("certificates/v1/")
        ):
            raise WitnessArchiveError("untrusted archive reference")
        result = self.s3.get_object(
            Bucket=ref.bucket, Key=ref.key, VersionId=ref.version_id
        )
        if result.get("VersionId") != ref.version_id:
            raise WitnessArchiveError("archive returned a different S3 version")
        declared = result.get("ContentLength")
        if not isinstance(declared, int) or not 0 < declared <= MAX_WITNESS:
            raise WitnessArchiveError("missing or oversized witness bytes")
        body = result.get("Body")
        if body is None:
            raise WitnessArchiveError("missing witness body")
        try:
            raw = body.read(MAX_WITNESS + 1)
        finally:
            body.close()
        if (
            not isinstance(raw, bytes) or len(raw) != declared
            or hashlib.sha256(raw).hexdigest() != ref.object_sha256
        ):
            raise WitnessArchiveError("witness version is truncated or modified")
        return raw
