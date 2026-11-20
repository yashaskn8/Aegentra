"""Validator-only immutable advisory scan receipt.

Revision ID: 0008_scan_receipts
Revises: 0007_guest_custody
"""
from alembic import op
import sqlalchemy as sa


revision = "0008_scan_receipts"
down_revision = "0007_guest_custody"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_receipts",
        sa.Column("org_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("job_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("generation", sa.BigInteger, primary_key=True),
        sa.Column("result_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("source_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("toolchain_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("coverage", sa.String(16), nullable=False),
        sa.Column("finding_count", sa.Integer, nullable=False),
        sa.Column("reason", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id", "job_id", "generation"],
            ["guest_attempts.org_id", "guest_attempts.job_id", "guest_attempts.generation"],
        ),
        sa.CheckConstraint("octet_length(result_sha256) = 32", name="scan_receipt_result_hash"),
        sa.CheckConstraint("octet_length(source_sha256) = 32", name="scan_receipt_source_hash"),
        sa.CheckConstraint("octet_length(toolchain_sha256) = 32", name="scan_receipt_toolchain_hash"),
        sa.CheckConstraint("status IN ('COMPLETE','INCOMPLETE')", name="scan_receipt_status"),
        sa.CheckConstraint("coverage IN ('VERIFIED','UNKNOWN','UNSUPPORTED')", name="scan_receipt_coverage"),
        sa.CheckConstraint("finding_count BETWEEN 0 AND 2000", name="scan_receipt_finding_count"),
    )
    op.execute("ALTER TABLE scan_receipts ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE scan_receipts FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_scope ON scan_receipts "
        "USING (org_id = nullif(current_setting('aegentra.org_id', true), '')::uuid) "
        "WITH CHECK (org_id = nullif(current_setting('aegentra.org_id', true), '')::uuid)"
    )


def downgrade() -> None:
    op.drop_table("scan_receipts")
