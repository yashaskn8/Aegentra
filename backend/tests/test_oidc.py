import asyncio
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from aegentra.oidc import (
    OidcClient, OidcError, OidcSettings, authorization_url, csrf_for_session,
    pkce_challenge, verify_id_token,
)


def settings() -> OidcSettings:
    return OidcSettings(
        issuer="https://idp.example.test/",
        authorization_url="https://idp.example.test/authorize",
        token_url="https://idp.example.test/token",
        jwks_url="https://idp.example.test/keys",
        client_id="aegentra-test",
        client_secret="a-reasonably-long-development-test-secret",
        redirect_uri="https://aegentra.test/v1/auth/callback",
        csrf_key=b"a" * 32,
    )


def token(private_key: object, *, nonce: str = "challenge", issuer: str | None = None,
          audience: str = "aegentra-test", expired: bool = False) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "iss": issuer or settings().issuer,
            "aud": audience,
            "sub": "employee-123",
            "nonce": nonce,
            "iat": now - timedelta(minutes=4),
            "exp": now - timedelta(seconds=60) if expired else now + timedelta(minutes=4),
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "key-1"},
    )


def jwks_for(private_key: object) -> dict:
    numbers = private_key.public_key().public_numbers()

    def integer(value: int) -> str:
        import base64
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return {"keys": [{"kty": "RSA", "kid": "key-1", "alg": "RS256", "use": "sig",
                      "n": integer(numbers.n), "e": integer(numbers.e)}]}


def test_pkce_url_binds_state_nonce_and_s256() -> None:
    url = authorization_url(settings(), "my-state", "my-nonce", "my-verifier")
    params = parse_qs(urlsplit(url).query)
    assert params["response_type"] == ["code"]
    assert params["code_challenge_method"] == ["S256"]
    assert params["code_challenge"] == [pkce_challenge("my-verifier")]
    assert params["state"] == ["my-state"]
    assert params["nonce"] == ["my-nonce"]
    assert "my-verifier" not in url


@pytest.mark.parametrize("invalid", ["http://idp.test/authorize", "https://user:pass@idp.test/",
                                     "https://idp.test/authorize#frag"])
def test_reject_untrusted_endpoint_settings(invalid: str) -> None:
    from dataclasses import replace
    with pytest.raises(ValueError):
        replace(settings(), authorization_url=invalid)


def test_valid_id_token_is_accepted() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert verify_id_token(token(key), jwks_for(key), settings(), "challenge") == "employee-123"


@pytest.mark.parametrize("kind", ["nonce", "issuer", "audience", "expired", "key"])
def test_forged_or_inconsistent_id_token_is_rejected(kind: str) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    changes = {
        "nonce": {"nonce": "different"},
        "issuer": {"issuer": "https://other.example.test"},
        "audience": {"audience": "not-aegentra"},
        "expired": {"expired": True},
        "key": {},
    }
    encoded = token(other if kind == "key" else key, **changes[kind])
    with pytest.raises(OidcError):
        verify_id_token(encoded, jwks_for(key), settings(), "challenge")


def test_csrf_is_session_bound() -> None:
    assert csrf_for_session(b"a" * 32, "token-a") != csrf_for_session(b"a" * 32, "token-b")

@pytest.mark.parametrize("payload", [[], {"id_token": None}, {"id_token": 42}])
def test_token_exchange_rejects_unexpected_json_shape(payload: object) -> None:
    requests: list[str] = []

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(200, json=payload)

    client = OidcClient(settings(), transport=httpx.MockTransport(respond))
    with pytest.raises(OidcError):
        asyncio.run(client.authenticate("code", "verifier", "nonce"))
    assert requests == [settings().token_url]
