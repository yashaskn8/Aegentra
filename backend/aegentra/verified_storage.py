"""Independent byte-verifier contract. Run only under a separate trust identity.

The API never invokes this module on customer input. A verified checksum is
still not a signed attestation, independent approval, or release authorization.
"""
from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass

import rfc8785

from aegentra.content_manifest import ContentManifest
from aegentra.db import StagingPart
from aegentra.evidence_verifier import (
    EvidenceMismatch, VersionedBlobReader, verify_versioned_blob,
)


@dataclass(frozen=True)
class StorageProof:
    """Content and pinned-storage identities, unsigned pending custody validation."""

    content_sha256: str
    storage_sha256: str
    canonical_bytes: bytes
    status: str = "VERIFIED_BYTES_UNSIGNED"


def verify_staged_versions(
    *,
    content: ContentManifest,
    parts: Sequence[StagingPart],
    bucket: str,
    encryption_domain: str,
    trusted_reader_for: Callable[[StagingPart], VersionedBlobReader],
) -> StorageProof:
    """Recompute exact bytes from trusted bucket/key plus a pinned VersionId.

    Every unknown, missing, extra or mismatched part aborts. No mutable/latest
    object read is permitted, and no code from the blob is executed.
    """
    if not bucket or not encryption_domain:
        raise EvidenceMismatch("storage identity missing")
    expected = {part.path: part for part in content.parts}
    if len(expected) != len(content.parts) or len(parts) != len(expected):
        raise EvidenceMismatch("storage path set is incomplete")
    by_path = {part.path: part for part in parts}
    if set(by_path) != set(expected):
        raise EvidenceMismatch("storage path set mismatch")

    storage: list[dict] = []
    for path in sorted(expected):
        declared = expected[path]
        stored = by_path[path]
        if (
            not stored.version_id or not stored.object_key
            or stored.byte_length != declared.byte_length
            or stored.content_sha256.hex() != declared.sha256
            or stored.media_type != declared.media_type
        ):
            raise EvidenceMismatch("stored claim differs from content manifest")
        verified = verify_versioned_blob(
            reader=trusted_reader_for(stored),
            version_id=stored.version_id,
            expected_sha256=declared.sha256,
            expected_length=declared.byte_length,
        )
        storage.append({
            "path": path,
            "bucket": bucket,
            "key": stored.object_key,
            "version_id": verified.version_id,
            "sha256": verified.sha256,
            "byte_length": verified.byte_length,
            "media_type": declared.media_type,
            "encryption_domain": encryption_domain,
        })
    canonical = rfc8785.dumps({
        "schema": "aegentra.storage.v1",
        "content_sha256": content.sha256(),
        "parts": storage,
    })
    return StorageProof(
        content_sha256=content.sha256(),
        storage_sha256=hashlib.sha256(canonical).hexdigest(),
        canonical_bytes=canonical,
    )
