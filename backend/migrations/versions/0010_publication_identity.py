"""Extend protected publication identity with pinned origin and sealed receipt.

Revision ID: 0010_publication_identity
Revises: 0009_release
"""
from alembic import op
import sqlalchemy as sa


revision = "0010_publication_identity"
down_revision = "0009_release"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for field, length in (("origin_bucket", 63), ("origin_key_prefix", 160), ("resource_path", 160)):
        op.add_column("release_targets", sa.Column(field, sa.String(length)))
    for field, length in (
        ("origin_bucket", 63), ("origin_key", 256),
        ("origin_version_id", 256), ("receipt_version_id", 256),
    ):
        op.add_column("release_publications", sa.Column(field, sa.String(length)))
    op.add_column(
        "release_publications",
        sa.Column("status", sa.String(24), nullable=False, server_default="PENDING_SEAL"),
    )
    op.add_column("release_publications", sa.Column("receipt_sha256", sa.LargeBinary(32)))
    op.create_check_constraint(
        "release_publication_status", "release_publications",
        "status IN ('PENDING_SEAL','SEALED')",
    )
    op.create_check_constraint(
        "release_publication_receipt_length", "release_publications",
        "receipt_sha256 IS NULL OR octet_length(receipt_sha256) = 32",
    )


def downgrade() -> None:
    op.drop_constraint("release_publication_receipt_length", "release_publications")
    op.drop_constraint("release_publication_status", "release_publications")
    op.drop_column("release_publications", "receipt_sha256")
    op.drop_column("release_publications", "status")
    for name in ("receipt_version_id", "origin_version_id", "origin_key", "origin_bucket"):
        op.drop_column("release_publications", name)
    for name in ("resource_path", "origin_key_prefix", "origin_bucket"):
        op.drop_column("release_targets", name)
