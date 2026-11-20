"""Initial PostgreSQL schema. No production database connection is initialized here."""
from __future__ import annotations

from uuid import UUID, uuid4

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
