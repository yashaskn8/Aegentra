"""Bridge-only physical attempt journal and globally nonreusable AWS IDs.

Revision ID: 0007_guest_custody
Revises: 0006_scan_jobs
"""
from alembic import op
import sqlalchemy as sa


revision = "0007_guest_custody"
down_revision = "0006_scan_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "guest_attempts",
        sa.Column("org_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("job_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("generation", sa.BigInteger, primary_key=True),
        sa.Column("nonce_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("input_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("toolchain_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("account_id", sa.String(12), nullable=False),
        sa.Column("availability_zone", sa.String(32), nullable=False),
        sa.Column("subnet_id", sa.String(40), nullable=False),
        sa.Column("security_group_id", sa.String(40), nullable=False),
        sa.Column("kms_key_arn", sa.String(256), nullable=False),
        sa.Column("state", sa.String(24), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id", "job_id"], ["scan_jobs.org_id", "scan_jobs.id"]
        ),
        sa.CheckConstraint("generation > 0", name="guest_generation_positive"),
        sa.CheckConstraint("octet_length(nonce_sha256) = 32", name="guest_nonce_hash"),
        sa.CheckConstraint("octet_length(input_sha256) = 32", name="guest_input_hash"),
        sa.CheckConstraint("octet_length(toolchain_sha256) = 32", name="guest_toolchain_hash"),
        sa.CheckConstraint(
            "state IN ('RESERVED','VOLUMES_RECORDED','INSTANCE_RECORDED',"
            "'DETACHED_VERIFIED','QUARANTINED','DISPOSED')",
            name="guest_attempt_state",
        ),
    )
    op.create_table(
        "guest_resources",
        sa.Column("resource_id", sa.String(40), primary_key=True),
        sa.Column("org_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("job_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("generation", sa.BigInteger, nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id", "job_id", "generation"],
            ["guest_attempts.org_id", "guest_attempts.job_id", "guest_attempts.generation"],
        ),
        sa.UniqueConstraint(
            "org_id", "job_id", "generation", "kind",
            name="uq_guest_resource_per_attempt_kind",
        ),
        sa.CheckConstraint(
            "kind IN ('INPUT_EBS','OUTPUT_EBS','INSTANCE')", name="guest_resource_kind",
        ),
    )
    for table in ("guest_attempts", "guest_resources"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_scope ON {table} "
            "USING (org_id = nullif(current_setting('aegentra.org_id', true), '')::uuid) "
            "WITH CHECK (org_id = nullif(current_setting('aegentra.org_id', true), '')::uuid)"
        )


def downgrade() -> None:
    op.drop_table("guest_resources")
    op.drop_table("guest_attempts")
