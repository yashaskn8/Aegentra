"""Inert end-to-end reference origin: signed head, independent witness/veto,
exact versioned bytes, two fresh head challenges and no stale fallback.
"""
from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from aegentra.gateway_signatures import (
    AdmissionDenied, HeadSnapshot, VetoSnapshot, SignedHead, SignedVeto,
    head_message, veto_message,
)
from aegentra.protected_gateway import (
    EnrolledResource, ProtectedAdmission,
    delivery_headers, delivery_profile_sha256,
)
from aegentra.fixed_delivery import FixedStaticProfile, UnsupportedDelivery
from aegentra.origin_asgi import ProtectedOriginASGI
from aegentra.witness_crypto import (
    WitnessBody, signed_certificate_bytes, witness_message,
)


class Fixture:
    def __init__(self, *, script_route: bool = False):
        self.now = datetime.now(timezone.utc)
        self.script = b"const answer = 42;"
        profile = FixedStaticProfile(
            host="static.example.test",
            script_sha256=hashlib.sha256(self.script).hexdigest(),
            script_length=len(self.script),
        )
        self.content = self.script if script_route else profile.generated_html()
        self.resource = EnrolledResource(
            org_id=uuid4(), target_id=uuid4(), incarnation=uuid4(),
            host="static.example.test",
            path=profile.script_path if script_route else profile.entry_path,
            origin_bucket="independent-origin",
            allowed_origin_prefix="published/allowed/",
            witness_bucket="security-archive",
            content_type=(
                "text/javascript; charset=utf-8"
                if script_route else "text/html; charset=utf-8"
            ), fixed_profile=profile,
        )
        self.head_signer = ec.generate_private_key(ec.SECP256R1())
        self.veto_signer = ec.generate_private_key(ec.SECP256R1())
        self.witness_signer = ec.generate_private_key(ec.SECP256R1())
        def pub(key):
            return key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        self.head_pub = pub(self.head_signer)
        self.veto_pub = pub(self.veto_signer)
        self.witness_pub = pub(self.witness_signer)
        self.cert = WitnessBody(
            kind="aegentra.security.witness.v1",
            audience="aegentra-release-publication",
            incarnation=self.resource.incarnation,
            org_id=self.resource.org_id, target_id=self.resource.target_id,
            attempt_sequence=3, prior_published_revision=0,
            predecessor_witness_sha256="0" * 64,
            subject_sha256="1" * 64, approval_set_sha256="2" * 64,
            staging_sha256="3" * 64,
            content_sha256=hashlib.sha256(self.content).hexdigest(),
            delivery_profile_sha256=delivery_profile_sha256(
                delivery_headers(self.resource, self.content)
            ),
            security_root_generation=4,
            issued_at=self.now - timedelta(seconds=1),
            selection_deadline=self.now + timedelta(seconds=90),
        )
        certificate_signature = self.witness_signer.sign(
            witness_message(self.cert), ec.ECDSA(hashes.SHA256())
        )
        self.cert_raw = signed_certificate_bytes(self.cert, certificate_signature)
        self.head_calls = []
        self.veto_calls = []
        self.body_calls = 0
        self.changed_head = False
        self.stopped = False
        self.corrupt_origin = False
        self.corrupt_witness = False
        self.veto_slow = False
        self.veto_wrong_root = False

    async def head(self, nonce):
        self.head_calls.append(nonce)
        head = HeadSnapshot(
            kind="aegentra.authority.head.v1",
            audience="aegentra-protected-gateway", request_nonce=nonce,
            org_id=self.resource.org_id, target_id=self.resource.target_id,
            incarnation=self.resource.incarnation,
            destination_host=self.resource.host,
            resource_path=self.resource.path,
            mode="ENFORCED", guard="ACTIVE",
            published_revision=1 if not self.changed_head or len(self.head_calls) == 1 else 2,
            attempt_sequence=3,
            content_sha256=hashlib.sha256(self.content).hexdigest(),
            delivery_profile_sha256=self.cert.delivery_profile_sha256,
            witness_bucket=self.resource.witness_bucket,
            witness_key=(
                f"certificates/v1/{self.resource.org_id.hex}/"
                f"{self.resource.incarnation.hex}/{self.resource.target_id.hex}/"
                f"{3:020d}"
            ),
            witness_version_id="immutable-version-one",
            witness_sha256=hashlib.sha256(self.cert_raw).hexdigest(),
            origin_bucket=self.resource.origin_bucket,
            origin_key="published/allowed/entry",
            origin_version_id="source-version-two",
            issued_at=self.now,
            expires_at=self.now + timedelta(seconds=1),
        )
        signature = self.head_signer.sign(head_message(head), ec.ECDSA(hashes.SHA256()))
        return SignedHead(head, signature)

    async def veto(self, nonce):
        self.veto_calls.append(nonce)
        if self.veto_slow:
            await asyncio.sleep(1)
        body = VetoSnapshot(
            kind="aegentra.security.veto-state.v1",
            audience="aegentra-protected-gateway",
            request_nonce=nonce,
            org_id=self.resource.org_id,
            incarnation=self.resource.incarnation,
            root_generation=3 if self.veto_wrong_root else 4,
            veto_generation=7, state="STOP" if self.stopped else "CLEAR",
            issued_at=self.now, expires_at=self.now + timedelta(seconds=1),
        )
        return SignedVeto(
            body, self.veto_signer.sign(veto_message(body), ec.ECDSA(hashes.SHA256())),
        )

    async def witness(self, ref):
        assert ref.version_id == "immutable-version-one"
        return self.cert_raw + (b"x" if self.corrupt_witness else b"")

    async def origin(self, bucket, key, version):
        self.body_calls += 1
        assert (bucket, key, version) == (
            "independent-origin", "published/allowed/entry", "source-version-two",
        )
        return self.content + (b"x" if self.corrupt_origin else b"")

    def gate(self, **kwargs):
        return ProtectedAdmission(
            resource=self.resource,
            head_public_der=self.head_pub, veto_public_der=self.veto_pub,
            witness_public_der=self.witness_pub,
            fetch_head=self.head, fetch_veto=self.veto,
            fetch_witness=self.witness, fetch_origin=self.origin,
            clock=lambda: self.now, **kwargs,
        )

    async def check(self, **kwargs):
        params = {
            "method": "GET", "host": self.resource.host,
            "path": self.resource.path, "request_headers": {},
        }
        params.update(kwargs)
        return await self.gate().admit(**params)


def test_valid_admission_buffers_signed_response_and_checks_fresh_veto():
    f = Fixture()
    response = asyncio.run(f.check())
    assert response.body == f.content
    assert response.revision == 1 and response.attempt_sequence == 3
    assert response.headers["cache-control"] == "no-store, max-age=0"
    assert len(f.head_calls) == 2
    assert len(set(f.head_calls + f.veto_calls)) == 3
    assert f.body_calls == 1


@pytest.mark.parametrize("condition", [
    "stop", "changed_head", "origin", "witness", "wrong_root",
])
def test_gateway_fail_closed_on_independent_failure(condition):
    f = Fixture()
    if condition == "stop":
        f.stopped = True
    elif condition == "changed_head":
        f.changed_head = True
    elif condition == "origin":
        f.corrupt_origin = True
    elif condition == "witness":
        f.corrupt_witness = True
    else:
        f.veto_wrong_root = True
    with pytest.raises(AdmissionDenied):
        asyncio.run(f.check())


@pytest.mark.parametrize("case_args", [
    {"method": "HEAD"},
    {"method": "POST"},
    {"host": "other.example.test"},
    {"path": "/other.js"},
    {"request_headers": {"Range": "bytes=0-8"}},
    {"request_headers": {"If-None-Match": "abc"}},
    {"request_headers": {"If-Modified-Since": "yesterday"}},
])
def test_out_of_profile_request_cannot_reach_dependencies(case_args):
    f = Fixture()
    with pytest.raises(AdmissionDenied):
        asyncio.run(f.check(**case_args))
    assert not f.head_calls and not f.veto_calls and f.body_calls == 0


def test_required_external_veto_timeout_has_no_fallback():
    f = Fixture()
    f.veto_slow = True
    with pytest.raises(AdmissionDenied):
        asyncio.run(f.gate(max_decision_seconds=0.04).admit(
            method="GET", host=f.resource.host, path=f.resource.path,
            request_headers={},
        ))
    assert f.body_calls == 1


def test_reference_asgi_exposes_only_prechecked_bytes_or_503():
    async def invoke(app, *, host="static.example.test", raw_path=b"/index.html"):
        messages = []
        async def send(message):
            messages.append(message)
        await app({
            "type": "http", "scheme": "https", "method": "GET",
            "path": "/index.html", "raw_path": raw_path,
            "query_string": b"",
            "headers": [(b"host", host.encode())],
        }, lambda: None, send)
        return messages

    f = Fixture()
    sent = asyncio.run(invoke(ProtectedOriginASGI(f.gate())))
    assert sent[0]["status"] == 200
    assert sent[1]["body"] == f.content
    f.stopped = True
    rejected = asyncio.run(invoke(ProtectedOriginASGI(f.gate())))
    assert rejected[0]["status"] == 503
    assert f.content not in rejected[1]["body"]

    encoded = asyncio.run(invoke(ProtectedOriginASGI(f.gate()), raw_path=b"/%69ndex.html"))
    assert encoded[0]["status"] == 503


def test_digest_addressed_script_is_served_with_hash_only_csp():
    f = Fixture(script_route=True)
    response = asyncio.run(f.check())
    assert response.body == f.script
    assert f.resource.path.endswith(hashlib.sha256(f.script).hexdigest() + ".js")
    assert response.headers["content-type"] == "text/javascript; charset=utf-8"
    csp = response.headers["content-security-policy"]
    assert "script-src 'sha256-" in csp
    assert "'self'" not in csp
    assert "connect-src 'none'" in csp
    assert "worker-src 'none'" in csp


def test_gateway_refuses_unreviewed_html_and_wrong_js_bytes_before_veto():
    html = Fixture()
    html.content = b'<!doctype html><script src="/unreviewed.js"></script>'
    # Fixture signed hash now describes adversarial HTML, but the fixed
    # independently enrolled template check still denies it.
    with pytest.raises(AdmissionDenied, match="unqualified"):
        asyncio.run(html.check())
    assert html.veto_calls == []

    js = Fixture(script_route=True)
    js.content = b"const answer = 43;"
    with pytest.raises(AdmissionDenied, match="unqualified"):
        asyncio.run(js.check())
    assert js.veto_calls == []
