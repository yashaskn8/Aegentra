"""Inert exact-byte fixtures for independent version-locked evidence identity."""
import hashlib
import json
from uuid import uuid4

import pytest

from aegentra.content_manifest import ContentManifest
from aegentra.db import StagingPart
from aegentra.evidence_verifier import EvidenceMismatch
from aegentra.verified_storage import verify_staged_versions


SOURCE = b"const x = 1;"
DIGEST = hashlib.sha256(SOURCE).hexdigest()


def fixture():
    org_id, upload_id = uuid4(), uuid4()
    manifest = ContentManifest.model_validate({
        "schema_id": "aegentra.content.v1",
        "parts": [{
            "path": "main.js", "sha256": DIGEST,
            "byte_length": len(SOURCE), "media_type": "application/javascript",
        }],
        "edges": [],
    })
    staged = StagingPart(
        org_id=org_id, upload_id=upload_id, part_index=0,
        path="main.js", content_sha256=bytes.fromhex(DIGEST),
        byte_length=len(SOURCE), media_type="application/javascript",
        object_key=f"staging/{org_id.hex}/{upload_id.hex}/part-00",
        version_id="version-one",
    )
    return manifest, staged


class FakeReader:
    def __init__(self, chunks):
        self._chunks = chunks
        self.version = None

    def chunks(self, version_id):
        self.version = version_id
        yield from self._chunks


def test_trusted_byte_rehash_produces_distinct_storage_identity() -> None:
    manifest, staged = fixture()
    reader = FakeReader([SOURCE[:4], SOURCE[4:]])
    kwargs = {
        "content": manifest, "parts": [staged], "bucket": "independent-vault",
        "encryption_domain": "encryption-key-1",
        "trusted_reader_for": lambda part: reader,
    }
    first = verify_staged_versions(**kwargs)
    second = verify_staged_versions(**kwargs)
    assert first == second
    assert reader.version == "version-one"
    assert first.status == "VERIFIED_BYTES_UNSIGNED"
    assert first.content_sha256 == manifest.sha256()
    assert first.storage_sha256 != manifest.sha256()
    doc = json.loads(first.canonical_bytes)
    assert doc["parts"][0]["version_id"] == "version-one"


@pytest.mark.parametrize("tamper", ["wrong-bytes", "no-version", "extra-part", "wrong-digest"])
def test_storage_gaps_cannot_produce_verified_proof(tamper: str) -> None:
    manifest, staged = fixture()
    chunks = [SOURCE]
    parts = [staged]
    if tamper == "wrong-bytes":
        chunks = [b"const y = 1;"]
    elif tamper == "no-version":
        staged.version_id = None
    elif tamper == "extra-part":
        parts.append(staged)
    else:
        staged.content_sha256 = bytes(32)
    with pytest.raises(EvidenceMismatch):
        verify_staged_versions(
            content=manifest, parts=parts, bucket="independent-vault",
            encryption_domain="key-1",
            trusted_reader_for=lambda part: FakeReader(chunks),
        )
