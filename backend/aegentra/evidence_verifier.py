"""Verify exact bytes from a previously authorized object version.

The verifier consumes a server-owned bucket/key and a pinned version ID; client
provided object locations must never be passed to this layer. The caller owns
ticket authorization, immutable S3 permissions, and independent signature checks.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

from aegentra.intake import MAX_PART_BYTES

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class EvidenceMismatch(Exception):
    """A required piece of evidence was missing, ambiguous or inconsistent."""


@dataclass(frozen=True)
class VerifiedBlob:
    version_id: str
    sha256: str
    byte_length: int


class VersionedBlobReader(Protocol):
    """Trusted reader, already pinned to its configured bucket/key."""

    def chunks(self, version_id: str) -> Iterable[bytes]: ...


def verify_versioned_blob(
    *,
    reader: VersionedBlobReader,
    version_id: str,
    expected_sha256: str,
    expected_length: int,
) -> VerifiedBlob:
    if (
        not isinstance(version_id, str)
        or version_id in ("", "null") or len(version_id) > 256
    ):
        raise EvidenceMismatch("missing or invalid storage version")
    if not isinstance(expected_sha256, str) or not _DIGEST.fullmatch(expected_sha256):
        raise EvidenceMismatch("invalid digest")
    if type(expected_length) is not int or not 1 <= expected_length <= MAX_PART_BYTES:
        raise EvidenceMismatch("invalid expected length")

    hasher = hashlib.sha256()
    total = 0
    chunks = iter(reader.chunks(version_id))
    try:
        for chunk in chunks:
            if not isinstance(chunk, bytes):
                raise EvidenceMismatch("invalid byte stream")
            total += len(chunk)
            if total > expected_length or total > MAX_PART_BYTES:
                raise EvidenceMismatch("oversized blob")
            hasher.update(chunk)
    finally:
        # Do not depend on generator garbage collection to release a reader.
        close = getattr(chunks, "close", None)
        if callable(close):
            close()
    if total != expected_length:
        raise EvidenceMismatch("incomplete blob")
    digest = hasher.hexdigest()
    if digest != expected_sha256:
        raise EvidenceMismatch("blob digest mismatch")
    return VerifiedBlob(version_id=version_id, sha256=digest, byte_length=total)
