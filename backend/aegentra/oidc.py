"""OIDC code-flow client: pinned endpoints, PKCE S256, and verified ID tokens.

The IdP is a configured trust root, never discovered from request parameters.
No ID token is treated as an Aegentra authorization role.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlsplit

import httpx
import jwt


class OidcError(Exception):
    """Authentication was not verifiable; no session may be issued."""


def _require_https(url: str) -> None:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.query
    ):
        raise ValueError("OIDC endpoints must be explicit HTTPS URLs")


@dataclass(frozen=True)
class OidcSettings:
    issuer: str
    authorization_url: str
    token_url: str
    jwks_url: str
    client_id: str
    client_secret: str
    redirect_uri: str
    csrf_key: bytes

    def __post_init__(self) -> None:
        for url in (
            self.issuer,
            self.authorization_url,
            self.token_url,
            self.jwks_url,
            self.redirect_uri,
        ):
            _require_https(url)
        if urlsplit(self.redirect_uri).path != "/v1/auth/callback":
            raise ValueError("redirect_uri must use the registered callback path")
        if not self.client_id or len(self.client_secret) < 24:
            raise ValueError("OIDC requires a client ID and a strong client secret")
        if len(self.csrf_key) < 32:
            raise ValueError("CSRF HMAC key must be at least 32 bytes")

    @property
    def origin(self) -> str:
        parsed = urlsplit(self.redirect_uri)
        return f"{parsed.scheme}://{parsed.netloc}"

    @classmethod
    def from_env(cls) -> "OidcSettings | None":
        if not os.getenv("AEGENTRA_OIDC_ISSUER"):
            return None

        def required(name: str) -> str:
            value = os.environ.get(f"AEGENTRA_{name}")
            if not value:
                raise ValueError(f"Missing AEGENTRA_{name}")
            return value

        try:
            csrf_key = bytes.fromhex(required("CSRF_KEY_HEX"))
        except ValueError as exc:
            raise ValueError("AEGENTRA_CSRF_KEY_HEX must be hex") from exc

        return cls(
            issuer=required("OIDC_ISSUER"),
            authorization_url=required("OIDC_AUTHORIZATION_URL"),
            token_url=required("OIDC_TOKEN_URL"),
            jwks_url=required("OIDC_JWKS_URL"),
            client_id=required("OIDC_CLIENT_ID"),
            client_secret=required("OIDC_CLIENT_SECRET"),
            redirect_uri=required("OIDC_REDIRECT_URI"),
            csrf_key=csrf_key,
        )


def random_token() -> str:
    return secrets.token_urlsafe(32)


def token_digest(token: str) -> bytes:
    return hashlib.sha256(token.encode("ascii")).digest()


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def csrf_for_session(key: bytes, session_token: str) -> str:
    return hmac.new(key, ("csrf:" + session_token).encode("ascii"), hashlib.sha256).hexdigest()


def authorization_url(settings: OidcSettings, state: str, nonce: str, verifier: str) -> str:
    params = {
        "response_type": "code",
        "client_id": settings.client_id,
        "redirect_uri": settings.redirect_uri,
        "scope": "openid",
        "state": state,
        "nonce": nonce,
        "code_challenge": pkce_challenge(verifier),
        "code_challenge_method": "S256",
    }
    return settings.authorization_url + "?" + urlencode(params)


def verify_id_token(token: str, jwks: dict[str, Any], settings: OidcSettings, nonce: str) -> str:
    """Verify signature, allowed algorithm, issuer, audience, lifetime and nonce."""
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
            raise OidcError("unsupported signing header")
        keys = jwks.get("keys")
        if not isinstance(keys, list) or len(keys) > 32:
            raise OidcError("invalid JWKS key set")
        matching = [
            k for k in keys
            if isinstance(k, dict)
            and k.get("kid") == header["kid"]
            and k.get("kty") == "RSA"
            and k.get("use", "sig") == "sig"
            and k.get("alg", "RS256") == "RS256"
        ]
        if len(matching) != 1:
            raise OidcError("unrecognized or duplicate signing key")
        key = jwt.PyJWK.from_dict(matching[0], algorithm="RS256").key
        payload = jwt.decode(
            token,
            key=key,
            algorithms=["RS256"],
            issuer=settings.issuer,
            audience=settings.client_id,
            options={"require": ["iss", "aud", "sub", "exp", "iat", "nonce"]},
            leeway=30,
        )
        if payload["nonce"] != nonce:
            raise OidcError("invalid login nonce")
        audience = payload["aud"]
        if isinstance(audience, list) and len(audience) > 1:
            if payload.get("azp") != settings.client_id:
                raise OidcError("missing or wrong authorized party")
        subject = payload["sub"]
        if not isinstance(subject, str) or not 1 <= len(subject) <= 255:
            raise OidcError("invalid subject")
        return subject
    except (jwt.PyJWTError, ValueError, KeyError, TypeError) as exc:
        raise OidcError("unable to verify ID token") from exc


class OidcClient:
    def __init__(self, settings: OidcSettings, transport: httpx.AsyncBaseTransport | None = None):
        self.settings = settings
        self.transport = transport

    async def authenticate(self, code: str, verifier: str, nonce: str) -> str:
        """Exchange an authorization code and return only a verified IdP subject."""
        async with httpx.AsyncClient(
            transport=self.transport, timeout=5.0, follow_redirects=False
        ) as client:
            try:
                response = await client.post(
                    self.settings.token_url,
                    auth=(self.settings.client_id, self.settings.client_secret),
                    data={
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": self.settings.redirect_uri,
                        "code_verifier": verifier,
                    },
                )
                response.raise_for_status()
                if len(response.content) > 16_384:
                    raise OidcError("token response too large")
                payload = response.json()
                if not isinstance(payload, dict):
                    raise OidcError("invalid token response")
                token = payload.get("id_token")
                if not isinstance(token, str) or len(token) > 12_000:
                    raise OidcError("missing ID token")

                keys_response = await client.get(self.settings.jwks_url)
                keys_response.raise_for_status()
                if len(keys_response.content) > 65_536:
                    raise OidcError("JWKS response too large")
                jwks = keys_response.json()
                if not isinstance(jwks, dict):
                    raise OidcError("invalid JWKS payload")
                return verify_id_token(token, jwks, self.settings, nonce)
            except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
                raise OidcError("identity provider unavailable or invalid") from exc
