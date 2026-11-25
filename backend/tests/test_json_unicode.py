"""RFC 8785 Unicode scalar validation on inert JSON evidence."""
import json

import pytest

from aegentra.bounded_json import ManifestError, strict_json
from aegentra.lockfile_analysis import inspect_package_lock


@pytest.mark.parametrize("raw", [
    br'"\ud800"', br'"\udfff"', br'{"\ud800":1}',
    br'{"outer":[{"name":"\udfff"}]}', br'["\udc00\ud800"]',
    br'{"outer":{"\udfff":true}}',
])
def test_unpaired_surrogates_are_rejected(raw):
    with pytest.raises(ManifestError, match="invalid Unicode"):
        strict_json(raw)


@pytest.mark.parametrize("raw,expected", [
    (br'"\ud83d\ude00"', "😀"),
    (br'{"\ud83d\ude00":"\u00e9"}', {"😀": "é"}),
    (br'"\\ud800"', r"\ud800"),
    ('{"text":"漢字😀"}'.encode("utf-8"), {"text": "漢字😀"}),
    (br'[null,true,12,1.25,"\u0000"]', [None, True, 12, 1.25, "\x00"]),
])
def test_valid_scalar_and_nonstring_values_are_preserved(raw, expected):
    assert strict_json(raw) == expected


def test_paired_escape_and_literal_key_still_collide():
    raw = '{"😀":1,"\\ud83d\\ude00":2}'.encode("utf-8")
    with pytest.raises(ManifestError, match="duplicate"):
        strict_json(raw)


def test_invalid_scalar_in_lockfile_never_becomes_reviewable():
    raw = json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "fixture"},
        "node_modules/a": {"version": "1.0.0\ud800", "integrity": "sha512-" + "A" * 86 + "=="},
    }}).encode("utf-8")
    report = inspect_package_lock(raw)
    assert report.status == "INCOMPLETE"
    assert report.packages == ()
    assert report.gaps == ("invalid Unicode in JSON string",)
