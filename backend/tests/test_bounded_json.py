"""Byte-encoding and structural limits for inert JSON evidence."""
import json

import pytest

from aegentra.bounded_json import ManifestError, strict_json
from aegentra.lockfile_analysis import inspect_package_lock


@pytest.mark.parametrize("encoding", [
    "utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be",
    "utf-8-sig",
])
def test_noncanonical_wire_encoding_is_rejected(encoding):
    with pytest.raises(ManifestError, match="invalid JSON"):
        strict_json('{"key":"value"}'.encode(encoding))


@pytest.mark.parametrize("raw", [b'"\xff"', b'"\xed\xa0\x80"', b'"\xc0\x80"'])
def test_invalid_utf8_is_rejected(raw):
    with pytest.raises(ManifestError, match="invalid JSON"):
        strict_json(raw)


def test_valid_multibyte_text_and_escaped_structural_characters():
    data = {"text": '漢字 café \\"' + "[" * 200, "nested": [1, {"ok": True}]}
    raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
    assert strict_json(raw) == data
    assert strict_json(raw, max_bytes=len(raw)) == data
    with pytest.raises(ManifestError, match="size limit"):
        strict_json(raw, max_bytes=len(raw) - 1)


def test_nesting_boundary_is_preserved():
    valid = b"[" * 128 + b"0" + b"]" * 128
    value = strict_json(valid)
    for _ in range(128):
        value = value[0]
    assert value == 0
    with pytest.raises(ManifestError, match="nesting depth"):
        strict_json(b"[" + valid + b"]")


@pytest.mark.parametrize("raw,message", [
    (b'{"outer":{"a":1,"a":2}}', "duplicate JSON property"),
    (b'{"value":NaN}', "nonstandard JSON constant"),
    (b'{"value":1e10000}', "non-finite JSON number"),
    (b'{"value":' + b"9" * 5000 + b"}", "invalid JSON"),
])
def test_existing_rejection_contract_is_preserved(raw, message):
    with pytest.raises(ManifestError, match=message):
        strict_json(raw)


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "utf-16", "utf-32"])
def test_lockfile_consumer_fails_closed_on_invalid_encoding(encoding):
    raw = json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "fixture"},
        "node_modules/a": {"version": "1.0.0", "integrity": "sha512-" + "A" * 86 + "=="},
    }}).encode(encoding)
    report = inspect_package_lock(raw)
    if encoding == "utf-8":
        assert report.status == "REVIEWABLE"
        assert len(report.packages) == 1
        assert not report.gaps
    else:
        assert report.status == "INCOMPLETE"
        assert report.packages == ()
        assert report.gaps == ("invalid JSON",)
