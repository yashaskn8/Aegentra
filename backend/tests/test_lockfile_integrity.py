"""Synthetic npm integrity fixtures; never download or execute a package."""
import base64
import hashlib
import json

import pytest

from aegentra.lockfile_analysis import inspect_package_lock


def token(algorithm: str, digest: bytes) -> str:
    return algorithm + "-" + base64.b64encode(digest).decode("ascii")


def inspect(integrity: object):
    return inspect_package_lock(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "fixture"},
        "node_modules/a": {"version": "1.0.0", "integrity": integrity},
    }}).encode("utf-8"))


@pytest.mark.parametrize("algorithm,size", [("sha256", 32), ("sha384", 48), ("sha512", 64)])
def test_exact_digest_width_is_reviewable(algorithm, size):
    digest = hashlib.new(algorithm, b"inert fixture").digest()
    assert len(digest) == size
    integrity = token(algorithm, digest)
    report = inspect(integrity)
    assert report.status == "REVIEWABLE"
    assert report.gaps == ()
    assert report.packages[0].integrity == integrity


@pytest.mark.parametrize("algorithm,size", [("sha256", 32), ("sha384", 48), ("sha512", 64)])
@pytest.mark.parametrize("offset", [-1, 1])
def test_wrong_digest_width_is_incomplete(algorithm, size, offset):
    report = inspect(token(algorithm, bytes(size + offset)))
    assert report.status == "INCOMPLETE"
    assert report.gaps == ("INVALID_INTEGRITY",)
    assert report.packages == ()


@pytest.mark.parametrize("integrity", [
    "sha512-YWJj", "sha256-AAAA=", "sha384-" + "A" * 65,
    "sha512-" + "A" * 100_000, token("sha256", bytes(32)).rstrip("="),
    token("sha256", bytes(32))[:-2] + "B=",  # nonzero unused pad bits
    token("sha512", bytes(64))[:-3] + "B==",
    token("sha256", bytes(32)) + "=", "sha1-" + "A" * 28,
    "sha512-", "sha256-AAAA\n", 42,
])
def test_invalid_integrity_never_appears_reviewable(integrity):
    report = inspect(integrity)
    assert report.status == "INCOMPLETE"
    assert report.gaps == ("INVALID_INTEGRITY",)
    assert report.packages == ()


def test_absent_integrity_remains_an_explicit_gap():
    report = inspect(None)
    assert report.status == "INCOMPLETE"
    assert report.gaps == ("MISSING_INTEGRITY",)
    assert report.packages[0].integrity is None


def test_invalid_entry_keeps_mixed_inventory_incomplete():
    integrity = token("sha512", hashlib.sha512(b"inert fixture").digest())
    raw = json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "fixture"},
        "node_modules/a": {"version": "1.0.0", "integrity": integrity},
        "node_modules/b": {"version": "2.0.0", "integrity": "sha512-YWJj"},
    }}).encode("utf-8")
    report = inspect_package_lock(raw)
    assert report.status == "INCOMPLETE"
    assert report.gaps == ("INVALID_INTEGRITY",)
    assert [(item.path, item.integrity) for item in report.packages] == [
        ("node_modules/a", integrity),
    ]
