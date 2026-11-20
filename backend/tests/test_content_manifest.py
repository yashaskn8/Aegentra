import hashlib
import json

import pytest
from pydantic import ValidationError

from aegentra.content_manifest import (
    ContentManifest, ManifestError, parse_manifest_json, strict_json,
)
from aegentra.lockfile_analysis import inspect_package_lock


SHA = "a" * 64


def manifest(paths: list[str], edges: list[dict] | None = None) -> dict:
    return {
        "schema_id": "aegentra.content.v1",
        "parts": [
            {"path": p, "byte_length": 12, "sha256": SHA, "media_type": "application/javascript"}
            for p in paths
        ],
        "edges": edges or [],
    }


def test_canonical_digest_is_order_independent_but_byte_sensitive() -> None:
    a = ContentManifest.model_validate(manifest(["z.js", "a.js"], [
        {"source": "z.js", "target": "a.js"},
    ]))
    b = ContentManifest.model_validate(manifest(["a.js", "z.js"], [
        {"source": "z.js", "target": "a.js"},
    ]))
    assert a.canonical_bytes() == b.canonical_bytes()
    assert a.sha256() == hashlib.sha256(a.canonical_bytes()).hexdigest()
    modified = manifest(["a.js", "z.js"], [{"source": "z.js", "target": "a.js"}])
    modified["parts"][0]["sha256"] = "b" * 64
    assert ContentManifest.model_validate(modified).sha256() != a.sha256()


@pytest.mark.parametrize("invalid", [
    manifest(["x.js", "X.js"]),
    manifest(["a.js"], [{"source": "a.js", "target": "other.js"}]),
    manifest(["a.js"], [{"source": "a.js", "target": "a.js"}] * 2),
])
def test_ambiguous_content_or_edges_are_rejected(invalid: dict) -> None:
    with pytest.raises(ValidationError):
        ContentManifest.model_validate(invalid)


def test_reject_undeclared_media_and_unknown_fields() -> None:
    data = manifest(["a.js"])
    data["parts"][0]["media_type"] = "text/html"
    with pytest.raises(ValidationError):
        ContentManifest.model_validate(data)
    data = manifest(["a.js"])
    data["approved"] = True
    with pytest.raises(ValidationError):
        ContentManifest.model_validate(data)


def test_reject_duplicate_json_keys_even_in_nested_objects() -> None:
    with pytest.raises(ManifestError, match="duplicate"):
        strict_json(b'{"a":{"sha256":"a","sha256":"b"}}')
    with pytest.raises(ManifestError):
        strict_json(b'{"a":NaN}')


def test_parse_manifest_json_rejects_unknown_or_missing_parts() -> None:
    assert parse_manifest_json(json.dumps(manifest(["a.js"])).encode()).parts[0].path == "a.js"
    with pytest.raises(ValidationError):
        parse_manifest_json(json.dumps({"schema_id": "aegentra.content.v1", "parts": []}).encode())


def test_package_lock_v3_is_data_not_code() -> None:
    lock = {"lockfileVersion": 3, "packages": {
        "": {"name": "test"},
        "node_modules/a": {"version": "1.0.0", "integrity": "sha512-YWJj"},
    }}
    report = inspect_package_lock(json.dumps(lock).encode())
    assert report.status == "REVIEWABLE"
    assert len(report.packages) == 1
    assert report.packages[0].version == "1.0.0"


@pytest.mark.parametrize("payload,expected", [
    (b'{"lockfileVersion":2,"packages":{}}', "UNSUPPORTED_LOCKFILE_VERSION"),
    (b'{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0"}}}', "MISSING_INTEGRITY"),
    (b'{"lockfileVersion":3,"packages":{"../a":{"version":"1.0"}}}', "AMBIGUOUS_PACKAGE_PATH"),
    (b'{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1","integrity":"wrong"}}}', "INVALID_INTEGRITY"),
    (b'{"lockfileVersion":3,"packages":{"x":{},"x":{}}}', "duplicate JSON property"),
])
def test_lockfile_coverage_gaps_never_become_clean(payload: bytes, expected: str) -> None:
    report = inspect_package_lock(payload)
    assert report.status == "INCOMPLETE"
    assert expected in report.gaps
