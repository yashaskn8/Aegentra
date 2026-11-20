"""Investigation case grants with asset-scoped evidence relationships.

Revision ID: 0004_cases
Revises: 0003_audit
"""
from alembic import op
import sqlalchemy as sa


revision = "0004_cases"
down_revision = "0003_audit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_evidence_org_asset_id", "evidence", ["org_id", "asset_id", "id"]
    )
    op.create_table(
        "investigation_cases",
        sa.Column("org_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("asset_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(140), nullable=False),
        sa.Column("created_by", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("revision", sa.Integer, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id", "asset_id"], ["assets.org_id", "assets.id"]),
        sa.ForeignKeyConstraint(["org_id", "created_by"], ["identities.org_id", "identities.id"]),
        sa.UniqueConstraint("org_id", "asset_id", "id", name="uq_case_org_asset_id"),
        sa.CheckConstraint("status IN ('OPEN', 'CLOSED')", name="case_status"),
        sa.CheckConstraint("revision > 0", name="case_revision_positive"),
    )
    op.create_table(
        "case_memberships",
        sa.Column("org_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("case_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("identity_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("grant_type", sa.String(12), nullable=False),
        sa.ForeignKeyConstraint(["org_id", "case_id"], ["investigation_cases.org_id", "investigation_cases.id"]),
        sa.ForeignKeyConstraint(["org_id", "identity_id"], ["identities.org_id", "identities.id"]),
        sa.CheckConstraint("grant_type IN ('OWNER', 'ANALYST', 'VIEWER')", name="case_grant"),
    )
    op.create_table(
        "case_evidence",
        sa.Column("org_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("asset_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("case_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("evidence_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("linked_by", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("linked_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id", "asset_id", "case_id"],
            ["investigation_cases.org_id", "investigation_cases.asset_id", "investigation_cases.id"],
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "asset_id", "evidence_id"],
            ["evidence.org_id", "evidence.asset_id", "evidence.id"],
        ),
        sa.ForeignKeyConstraint(["org_id", "linked_by"], ["identities.org_id", "identities.id"]),
    )
    for table in ("investigation_cases", "case_memberships", "case_evidence"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_scope ON {table} "
            "USING (org_id = nullif(current_setting('aegentra.org_id', true), '')::uuid) "
            "WITH CHECK (org_id = nullif(current_setting('aegentra.org_id', true), '')::uuid)"
        )


def downgrade() -> None:
    op.drop_table("case_evidence")
    op.drop_table("case_memberships")
    op.drop_table("investigation_cases")
    op.drop_constraint("uq_evidence_org_asset_id", "evidence", type_="unique")
