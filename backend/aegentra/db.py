"""Initial PostgreSQL schema. No production database connection is initialized here."""
from __future__ import annotations

from uuid import UUID, uuid4
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer

from sqlalchemy import CheckConstraint, ForeignKeyConstraint, LargeBinary, String, Uuid, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    slug: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)


class Asset(Base):
    __tablename__ = "assets"

    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    slug: Mapped[str] = mapped_column(String(80), nullable=False)
    criticality: Mapped[str] = mapped_column(String(8), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        CheckConstraint("criticality IN ('LOW', 'MEDIUM', 'HIGH')", name="asset_criticality"),
        UniqueConstraint("org_id", "slug", name="uq_asset_org_slug"),
    )


class Evidence(Base):
    __tablename__ = "evidence"

    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    asset_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(["org_id", "asset_id"], ["assets.org_id", "assets.id"]),
        CheckConstraint("octet_length(digest) = 32", name="evidence_digest_length"),
    )


class Identity(Base):
    """Pre-enrolled identity: IdP claims never grant a role by themselves."""

    __tablename__ = "identities"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    issuer: Mapped[str] = mapped_column(String(256), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    membership_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (
        ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        UniqueConstraint("org_id", "id", name="uq_identity_org_id"),
        UniqueConstraint("issuer", "subject", name="uq_identity_issuer_subject"),
        CheckConstraint("role IN ('ADMIN', 'EDITOR', 'ANALYST', 'VIEWER')", name="identity_role"),
        CheckConstraint("membership_version > 0", name="identity_membership_version"),
    )


class LoginChallenge(Base):
    __tablename__ = "login_challenges"

    state_hash: Mapped[bytes] = mapped_column(LargeBinary(32), primary_key=True)
    browser_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    verifier: Mapped[str] = mapped_column(String(128), nullable=False)
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint("octet_length(state_hash) = 32", name="login_state_hash_length"),
        CheckConstraint("octet_length(browser_hash) = 32", name="login_browser_hash_length"),
    )


class BrowserSession(Base):
    __tablename__ = "browser_sessions"

    token_hash: Mapped[bytes] = mapped_column(LargeBinary(32), primary_key=True)
    identity_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    idle_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "identity_id"], ["identities.org_id", "identities.id"]
        ),
        CheckConstraint("octet_length(token_hash) = 32", name="session_token_hash_length"),
    )
