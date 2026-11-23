"""Read-only independent HTTP sampling: exact GET, signed current head and bytes."""
import asyncio
import hashlib
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from aegentra.fixed_delivery import FixedStaticProfile
from aegentra.gateway_signatures import HeadSnapshot, SignedHead, head_message
from aegentra.observation_crypto import ObserverCredential, verify_observation
from aegentra.observer_http import (
    KmsObserverSigner, NativeReadbackObserver, ReadbackUnavailable,
    observed_profile_sha256,
)
from aegentra.protected_gateway import delivery_profile_sha256


def fixture(body_override=None, headers_override=None, status=200):
    now = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)
    js = b"const x = 42;"
    profile = FixedStaticProfile(
        host="static.example.test",
        script_sha256=hashlib.sha256(js).hexdigest(),
        script_length=len(js),
    )
    html = profile.generated_html()
    actual_body = html if body_override is None else body_override(html)
    headers = profile.headers(path="/index.html", content=html)
    if headers_override:
        headers = headers_override(headers.copy())
    org, target, incarnation = uuid4(), uuid4(), uuid4()
    head_key = ec.generate_private_key(ec.SECP256R1())
    observer_key = ec.generate_private_key(ec.SECP256R1())

    def public(key):
        return key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    async def fetch_head(nonce):
        body = HeadSnapshot(
            kind="aegentra.authority.head.v1",
            audience="aegentra-protected-gateway",
            request_nonce=nonce,
            incarnation=incarnation, org_id=org, target_id=target,
            destination_host=profile.host,
            resource_path="/index.html",
            mode="ENFORCED", guard="ACTIVE",
            published_revision=4, attempt_sequence=9,
            content_sha256=hashlib.sha256(html).hexdigest(),
            delivery_profile_sha256=delivery_profile_sha256(
                profile.headers(path="/index.html", content=html)
            ),
            fixed_bundle_sha256=profile.manifest_sha256(),
            witness_bucket="security-archive",
            witness_key="certificates/record",
            witness_version_id="immutable-version",
            witness_sha256="c" * 64,
            origin_bucket="protected-origin",
            origin_key="published/app",
            origin_version_id="origin-v1",
            issued_at=now, expires_at=now + timedelta(seconds=1),
        )
        return SignedHead(
            body,
            head_key.sign(head_message(body), ec.ECDSA(hashes.SHA256())),
        )

    class Kms:
        def sign(self, **kwargs):
            return {"Signature": observer_key.sign(
                kwargs["Message"], ec.ECDSA(hashes.SHA256())
            )}

    observer = NativeReadbackObserver(
        org_id=org, target_id=target, incarnation=incarnation,
        profile=profile, path="/index.html",
        cohort="independent-edge-one",
        observer_key_id="outside-observer-credential",
        head_key_der=public(head_key), fetch_head=fetch_head,
        signer=KmsObserverSigner(
            kms=Kms(), key_id="pinned-observer-kms",
            public_der=public(observer_key),
        ), clock=lambda: now,
    )

    def handler(request):
        assert request.method == "GET"
        assert str(request.url) == "https://static.example.test/index.html"
        assert request.headers["accept-encoding"] == "identity"
        assert "if-none-match" not in request.headers
        return httpx.Response(
            status, headers=headers, stream=httpx.ByteStream(actual_body),
            request=request,
        )

    credential = ObserverCredential(
        key_id="outside-observer-credential",
        public_key_der=public(observer_key),
        independently_enrolled=True,
    )
    return observer, credential, httpx.MockTransport(handler), now, profile, html


async def measure(observer, transport):
    async with httpx.AsyncClient(
        transport=transport, trust_env=False, follow_redirects=False,
    ) as client:
        return await observer.measure(client)


def test_signed_observer_reports_exact_original_representation():
    observer, credential, transport, now, profile, html = fixture()
    envelope = asyncio.run(measure(observer, transport))
    result = verify_observation(envelope, observer=credential, now=now)
    assert result.complete_bytes
    assert result.http_status == 200
    assert result.observed_sha256 == hashlib.sha256(html).hexdigest()
    assert result.observed_sha256 == result.expected_sha256
    assert result.observed_profile_sha256 == result.expected_profile_sha256
    assert result.cohort == "independent-edge-one"
    assert result.published_revision == 4


def test_same_length_changed_bytes_produce_signed_mismatch():
    observer, credential, transport, now, profile, html = fixture(
        body_override=lambda raw: b"X" + raw[1:],
    )
    result = verify_observation(
        asyncio.run(measure(observer, transport)),
        observer=credential, now=now,
    )
    assert result.complete_bytes and result.http_status == 200
    assert result.observed_sha256 != result.expected_sha256
    assert result.observed_profile_sha256 == result.expected_profile_sha256


def test_changed_response_headers_produce_signed_profile_mismatch():
    observer, credential, transport, now, profile, html = fixture(
        headers_override=lambda data: {
            **data, "content-security-policy": "default-src 'self'"
        },
    )
    result = verify_observation(
        asyncio.run(measure(observer, transport)),
        observer=credential, now=now,
    )
    assert result.complete_bytes and result.http_status == 200
    assert result.observed_profile_sha256 != result.expected_profile_sha256


def test_non_success_response_is_coverage_gap_not_matching_content():
    observer, credential, transport, now, profile, html = fixture(status=503)
    result = verify_observation(
        asyncio.run(measure(observer, transport)),
        observer=credential, now=now,
    )
    assert result.http_status == 503


def test_network_failure_cannot_forge_clean_observation():
    observer, credential, _, now, profile, html = fixture()
    def broken(req):
        raise httpx.ConnectError("simulated no-route", request=req)
    with pytest.raises(ReadbackUnavailable):
        asyncio.run(measure(observer, httpx.MockTransport(broken)))


def test_stale_or_wrong_head_nonce_cannot_be_used():
    observer, credential, transport, now, profile, html = fixture()
    original_fetch = observer.fetch_head

    async def wrong(_):
        return await original_fetch("x" * 43)
    observer.fetch_head = wrong
    with pytest.raises(ReadbackUnavailable):
        asyncio.run(measure(observer, transport))


@pytest.mark.parametrize("invalid_timeout", [
    float("nan"), float("inf"), float("-inf"), 0, -1, 2.01,
    True, False, "2", None,
])
def test_observer_rejects_unbounded_or_non_numeric_timeout_before_network(invalid_timeout):
    observer, _, _, _, _, _ = fixture()
    options = dict(vars(observer))
    options["timeout"] = invalid_timeout
    with pytest.raises(ValueError, match="observer enrolled profile is incomplete"):
        NativeReadbackObserver(**options)


def test_observer_accepts_finite_bounded_timeout():
    observer, _, _, _, _, _ = fixture()
    options = dict(vars(observer))
    for timeout in (0.001, 1, 2.0):
        assert NativeReadbackObserver(**{**options, "timeout": timeout}).timeout == timeout
