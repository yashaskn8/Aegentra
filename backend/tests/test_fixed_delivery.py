"""SA-1.1 D1: generated fixed HTML + one classic digest-pinned JS."""
import base64
import hashlib

import pytest

from aegentra.fixed_delivery import (
    FixedStaticProfile, MAX_SCRIPT_BYTES, UnsupportedDelivery,
)


def profile(script: bytes = b"const safeFixture = 1;") -> FixedStaticProfile:
    return FixedStaticProfile(
        host="pilot.example.test",
        script_sha256=hashlib.sha256(script).hexdigest(),
        script_length=len(script),
    )


def test_fixed_entry_has_only_a_digest_addressed_integrity_checked_script():
    script = b"const safeFixture = 1;"
    item = profile(script)
    html = item.generated_html()
    assert html.count(b"<script") == 1
    assert b"integrity=\"sha256-" in html
    assert item.script_path.encode("ascii") in html
    assert item.sri.encode("ascii") in html
    assert b"serviceWorker" not in html
    assert b"<base" not in html
    assert b"<iframe" not in html
    assert item.check_representation(path="/index.html", content=html) == (
        "text/html; charset=utf-8"
    )
    assert item.check_representation(
        path=item.script_path, content=script,
    ) == "text/javascript; charset=utf-8"
    assert "'self'" not in item.csp
    assert "'unsafe-inline'" not in item.csp
    assert "script-src 'sha256-" in item.csp
    assert "worker-src 'none'" in item.csp
    assert "connect-src 'none'" in item.csp
    assert "object-src 'none'" in item.csp
    assert "base-uri 'none'" in item.csp
    assert "frame-ancestors 'none'" in item.csp
    assert "form-action 'none'" in item.csp
    assert item.headers(path="/index.html", content=html)["content-length"] == str(len(html))
    assert item.manifest()["entry_sha256"] == hashlib.sha256(html).hexdigest()
    assert item.manifest_sha256() == profile(script).manifest_sha256()


@pytest.mark.parametrize("bad", [
    "not-hex", "A" * 64, "a" * 63, "a" * 65,
])
def test_bad_script_hash_rejected(bad):
    with pytest.raises(UnsupportedDelivery):
        FixedStaticProfile(
            host="pilot.example.test", script_sha256=bad, script_length=10,
        )


@pytest.mark.parametrize("length", [0, -1, MAX_SCRIPT_BYTES + 1, True, 1.5])
def test_script_length_must_be_a_positive_bounded_integer(length):
    with pytest.raises(UnsupportedDelivery):
        FixedStaticProfile(
            host="pilot.example.test", script_sha256="a" * 64,
            script_length=length,
        )


@pytest.mark.parametrize("host", [
    "https://pilot.example.test", "pilot.example.test:443",
    "*.example.test", "PILOT.example.test", "",
])
def test_not_arbitrary_host_or_url(host):
    with pytest.raises(UnsupportedDelivery):
        FixedStaticProfile(
            host=host, script_sha256="a" * 64, script_length=12,
        )


def test_rejects_unapproved_html_variants_and_non_enrolled_paths():
    item = profile()
    html = item.generated_html()
    for changed in (
        html + b" ",
        html.replace(b"</head>", b"<script>alert(1)</script></head>"),
        b"<html><body><script src=\"/other.js\"></script></body></html>",
    ):
        with pytest.raises(UnsupportedDelivery):
            item.headers(path="/index.html", content=changed)
    for path in (
        "/", "/index.html/", "/other.js", "/favicon.ico",
        item.script_path + "?v=1", "/sw.js",
    ):
        with pytest.raises(UnsupportedDelivery):
            item.headers(path=path, content=b"x")


def test_mismatched_script_does_not_inherit_trusted_header_profile():
    item = profile()
    with pytest.raises(UnsupportedDelivery):
        item.headers(path=item.script_path, content=b"const other = 2;")
    with pytest.raises(UnsupportedDelivery):
        item.headers(path=item.script_path, content=b"")


def test_exact_maximum_script_size_supported_but_over_limit_rejected():
    script = b";" * MAX_SCRIPT_BYTES
    item = profile(script)
    assert item.check_representation(path=item.script_path, content=script) == (
        "text/javascript; charset=utf-8"
    )
    with pytest.raises(UnsupportedDelivery):
        item.check_representation(path=item.script_path, content=script + b";")
