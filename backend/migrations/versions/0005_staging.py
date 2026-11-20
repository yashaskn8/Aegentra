"""Persist upload declarations and pinned object-version claims.

Revision ID: 0005_staging
Revises: 0004_cases
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "0005_staging"
down_revision = "0004_cases"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "staging_uploads",
        sa.Column("org_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("asset_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("issued_by", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("content_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("content_manifest", JSONB, nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id", "asset_id"], ["assets.org_id", "assets.id"]),
        sa.ForeignKeyConstraint(["org_id", "issued_by"], ["identities.org_id", "identities.id"]),
        sa.CheckConstraint("octet_length(content_digest) = 32", name="staging_content_digest_length"),
        sa.CheckConstraint(
            "status IN ('ISSUED', 'AWAITING_VERIFICATION', 'REJECTED')",
            name="staging_status",
        ),
    )
    op.create_index("ix_staging_expires", "staging_uploads", ["expires_at"])
    op.create_table(
        "staging_parts",
        sa.Column("org_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("upload_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("part_index", sa.Integer, primary_key=True),
        sa.Column("path", sa.String(128), nullable=False),
        sa.Column("content_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("byte_length", sa.Integer, nullable=False),
        sa.Column("media_type", sa.String(64), nullable=False),
        sa.Column("object_key", sa.String(256), nullable=False),
        sa.Column("version_id", sa.String(256)),
        sa.ForeignKeyConstraint(
            ["org_id", "upload_id"], ["staging_uploads.org_id", "staging_uploads.id"]
        ),
        sa.UniqueConstraint("org_id", "upload_id", "path", name="uq_staging_path"),
        sa.UniqueConstraint("org_id", "upload_id", "object_key", name="uq_staging_key"),
        sa.CheckConstraint("octet_length(content_sha256) = 32", name="staging_part_digest_length"),
        sa.CheckConstraint("byte_length > 0 AND byte_length <= 10485760", name="staging_part_length"),
    )
    for table in ("staging_uploads", "staging_parts"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_scope ON {table} "
            "USING (org_id = nullif(current_setting('aegentra.org_id', true), '')::uuid) "
            "WITH CHECK (org_id = nullif(current_setting('aegentra.org_id', true), '')::uuid)"
        )


def downgrade() -> None:
    op.drop_table("staging_parts")
    op.drop_index("ix_staging_expires", table_name="staging_uploads")
    op.drop_table("staging_uploads")
