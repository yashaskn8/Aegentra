"""Tenant-scoped asset and evidence foundation.

Revision ID: 0001_foundation
Revises:
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_foundation"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("slug", sa.String(80), nullable=False, unique=True),
    )
    op.create_table(
        "assets",
        sa.Column("org_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("slug", sa.String(80), nullable=False),
        sa.Column("criticality", sa.String(8), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.CheckConstraint("criticality IN ('LOW', 'MEDIUM', 'HIGH')", name="asset_criticality"),
        sa.UniqueConstraint("org_id", "slug", name="uq_asset_org_slug"),
    )
    op.create_table(
        "evidence",
        sa.Column("org_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("asset_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("digest", sa.LargeBinary(32), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.ForeignKeyConstraint(["org_id", "asset_id"], ["assets.org_id", "assets.id"]),
        sa.CheckConstraint("octet_length(digest) = 32", name="evidence_digest_length"),
    )
    for table in ("assets", "evidence"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_scope ON {table} "
            "USING (org_id = nullif(current_setting('aegentra.org_id', true), '')::uuid) "
            "WITH CHECK (org_id = nullif(current_setting('aegentra.org_id', true), '')::uuid)"
        )


def downgrade() -> None:
    op.drop_table("evidence")
    op.drop_table("assets")
    op.drop_table("organizations")
