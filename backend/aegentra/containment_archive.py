"""Version-locked containment proof archive in the independent security account.

This adapter only creates/reads exact immutable evidence. It cannot issue
STOP, report containment, authorize case status, or grant KMS signing access.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from aegentra.incident_containment import ContainmentArchiveRef

MAX_PROOF_BYTES = 64 * 1024


class ContainmentArchiveError(ValueError):
    pass


@dataclass(frozen=True)
class ContainmentProofArchive:
    s3: Any
    sts: Any
    bucket: str
    security_account_id: str

    def _verify_account(self) -> None:
        if (
            len(self.security_account_id) != 12
            or not self.security_account_id.isdecimal()
            or self.sts.get_caller_identity().get("Account")
            != self.security_account_id
        ):
            raise ContainmentArchiveError("independent incident archive account unavailable")

    @staticmethod
    def key_for(*, org_id: UUID, case_id: UUID, generation: int) -> str:
        if generation <= 0:
            raise ContainmentArchiveError("STOP generation is required")
        return f"incidents/v1/{org_id.hex}/{case_id.hex}/{generation:020d}"

    def append(
        self, *, org_id: UUID, case_id: UUID, generation: int,
        canonical_proof: bytes,
    ) -> ContainmentArchiveRef:
        self._verify_account()
        if not isinstance(canonical_proof, bytes) or not (
            0 < len(canonical_proof) <= MAX_PROOF_BYTES
        ):
            raise ContainmentArchiveError("bounded proof bytes are mandatory")
        key = self.key_for(
            org_id=org_id, case_id=case_id, generation=generation,
        )
        digest = hashlib.sha256(canonical_proof).digest()
        response = self.s3.put_object(
            Bucket=self.bucket, Key=key, Body=canonical_proof,
            ContentType="application/json",
            IfNoneMatch="*",
            ChecksumSHA256=base64.b64encode(digest).decode("ascii"),
        )
        version = response.get("VersionId")
        if not isinstance(version, str) or version in ("", "null"):
            raise ContainmentArchiveError("S3 did not return an immutable proof version")
        return ContainmentArchiveRef(
            bucket=self.bucket, key=key,
            version_id=version, sha256=digest.hex(),
        )

    def read_exact(
        self, ref: ContainmentArchiveRef, *,
        org_id: UUID, case_id: UUID, generation: int,
    ) -> bytes:
        self._verify_account()
        expected_key = self.key_for(
            org_id=org_id, case_id=case_id, generation=generation,
        )
        if (
            ref.bucket != self.bucket or ref.key != expected_key
            or not ref.version_id or ref.version_id == "null"
            or len(ref.sha256) != 64
        ):
            raise ContainmentArchiveError("incident archive reference is not enrolled")
        result = self.s3.get_object(
            Bucket=self.bucket, Key=expected_key,
            VersionId=ref.version_id,
        )
        if result.get("VersionId") != ref.version_id:
            raise ContainmentArchiveError("different S3 proof version returned")
        length = result.get("ContentLength")
        if not isinstance(length, int) or not 0 < length <= MAX_PROOF_BYTES:
            raise ContainmentArchiveError("incident proof is unavailable or too large")
        stream = result.get("Body")
        if stream is None:
            raise ContainmentArchiveError("incident proof body is missing")
        try:
            raw = stream.read(MAX_PROOF_BYTES + 1)
        finally:
            stream.close()
        if (
            not isinstance(raw, bytes) or len(raw) != length
            or not hmac.compare_digest(
                hashlib.sha256(raw).hexdigest(), ref.sha256,
            )
        ):
            raise ContainmentArchiveError("exact incident proof bytes did not verify")
        return raw
