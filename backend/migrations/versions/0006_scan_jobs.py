"""Scan job generations, bounded leases and stale-result fencing.

Revision ID: 0006_scan_jobs
Revises: 0005_staging
"""
from alembic import op
import sqlalchemy as sa


revision = "0006_scan_jobs"
down_revision = "0005_staging"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_jobs",
        sa.Column("org_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("upload_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempt_generation", sa.BigInteger, nullable=False),
        sa.Column("attempts", sa.Integer, nullable=False),
        sa.Column("lease_nonce", sa.String(64)),
        sa.Column("lease_expires", sa.DateTime(timezone=True)),
        sa.Column("attempt_deadline", sa.DateTime(timezone=True)),
        sa.Column("result_sha256", sa.LargeBinary(32)),
        sa.ForeignKeyConstraint(
            ["org_id", "upload_id"], ["staging_uploads.org_id", "staging_uploads.id"]
        ),
        sa.CheckConstraint(
            "status IN ('QUEUED','LEASED','PENDING_TRUSTED_VALIDATION','UNKNOWN')",
            name="scan_job_status",
        ),
        sa.CheckConstraint("attempts BETWEEN 0 AND 3", name="scan_job_attempts"),
        sa.CheckConstraint("attempt_generation >= 0", name="scan_job_generation"),
        sa.CheckConstraint(
            "result_sha256 IS NULL OR octet_length(result_sha256) = 32",
            name="scan_job_result_hash",
        ),
    )
    op.create_index("ix_scan_job_ready", "scan_jobs", ["status", "lease_expires"])
    op.execute("ALTER TABLE scan_jobs ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE scan_jobs FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_scope ON scan_jobs "
        "USING (org_id = nullif(current_setting('aegentra.org_id', true), '')::uuid) "
        "WITH CHECK (org_id = nullif(current_setting('aegentra.org_id', true), '')::uuid)"
    )


def downgrade() -> None:
    op.drop_index("ix_scan_job_ready", table_name="scan_jobs")
    op.drop_table("scan_jobs")
