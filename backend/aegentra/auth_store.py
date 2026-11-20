"""Single-use login challenges and revocable server-side browser sessions."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import and_, delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegentra.db import BrowserSession, Identity, LoginChallenge
from aegentra.oidc import random_token, token_digest


class AuthenticationError(Exception):
    pass


class NotEnrolledError(Exception):
    pass


@dataclass(frozen=True)
class Principal:
    identity_id: UUID
    org_id: UUID
    role: str


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def valid_cookie(token: str | None) -> bool:
    return bool(token and re.fullmatch(r"[A-Za-z0-9_-]{43}", token))


class AuthStore:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]):
        self.sessions = sessions

    async def begin_login(self, state: str, browser: str, verifier: str, nonce: str) -> None:
        async with self.sessions() as session:
            async with session.begin():
                # Expired one-time attempts do not need long-term retention.
                await session.execute(
                    delete(LoginChallenge).where(LoginChallenge.expires_at < utc_now())
                )
                session.add(
                    LoginChallenge(
                        state_hash=token_digest(state),
                        browser_hash=token_digest(browser),
                        verifier=verifier,
                        nonce=nonce,
                        expires_at=utc_now() + timedelta(minutes=5),
                    )
                )

    async def consume_login(self, state: str, browser: str) -> tuple[str, str]:
        if not valid_cookie(state) or not valid_cookie(browser):
            raise AuthenticationError("invalid login transaction")
        async with self.sessions() as session:
            async with session.begin():
                row = (
                    await session.execute(
                        delete(LoginChallenge)
                        .where(
                            LoginChallenge.state_hash == token_digest(state),
                            LoginChallenge.browser_hash == token_digest(browser),
                            LoginChallenge.expires_at > utc_now(),
                        )
                        .returning(LoginChallenge.verifier, LoginChallenge.nonce)
                    )
                ).one_or_none()
                if row is None:
                    raise AuthenticationError("invalid or used login transaction")
                return row.verifier, row.nonce

    async def create_session(self, issuer: str, subject: str) -> str:
        async with self.sessions() as session:
            async with session.begin():
                identity = await session.scalar(
                    select(Identity).where(
                        Identity.issuer == issuer,
                        Identity.subject == subject,
                        Identity.active.is_(True),
                    )
                )
                if identity is None:
                    raise NotEnrolledError("identity is not enrolled")
                now = utc_now()
                token = random_token()
                session.add(
                    BrowserSession(
                        token_hash=token_digest(token),
                        identity_id=identity.id,
                        org_id=identity.org_id,
                        membership_version=identity.membership_version,
                        created_at=now,
                        expires_at=now + timedelta(hours=8),
                        idle_expires_at=now + timedelta(minutes=30),
                    )
                )
                return token

    async def authenticate(self, token: str | None) -> Principal:
        if not valid_cookie(token):
            raise AuthenticationError("missing or invalid session")
        async with self.sessions() as session:
            async with session.begin():
                row = (
                    await session.execute(
                        select(BrowserSession, Identity)
                        .join(
                            Identity,
                            and_(
                                BrowserSession.identity_id == Identity.id,
                                BrowserSession.org_id == Identity.org_id,
                            ),
                        )
                        .where(BrowserSession.token_hash == token_digest(token))
                        .with_for_update(of=BrowserSession)
                    )
                ).one_or_none()
                if row is None:
                    raise AuthenticationError("session not found")
                browser, identity = row
                now = utc_now()
                if (
                    not identity.active
                    or browser.membership_version != identity.membership_version
                    or now >= browser.expires_at
                    or now >= browser.idle_expires_at
                ):
                    raise AuthenticationError("expired or revoked session")
                browser.idle_expires_at = min(browser.expires_at, now + timedelta(minutes=30))
                return Principal(identity_id=identity.id, org_id=identity.org_id, role=identity.role)

    async def revoke(self, token: str) -> None:
        if not valid_cookie(token):
            return
        async with self.sessions() as session:
            async with session.begin():
                await session.execute(
                    delete(BrowserSession).where(BrowserSession.token_hash == token_digest(token))
                )
