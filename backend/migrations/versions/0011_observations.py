"""Independent signed readback observations and tenant-scoped receipts.

Revision ID: 0011_observations
Revises: 0010_publication_identity
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "0011_observations"
down_revision = "0010_publication_identity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "release_observations",
        sa.Column("org_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("target_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("incarnation", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("published_revision", sa.BigInteger, nullable=False),
        sa.Column("attempt_sequence", sa.BigInteger, nullable=False),
        sa.Column("observer_key_id", sa.String(128), nullable=False),
        sa.Column("cohort", sa.String(64), nullable=False),
        sa.Column("expected_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("observed_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("expected_profile_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("observed_profile_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("http_status", sa.Integer, nullable=False),
        sa.Column("complete_bytes", sa.Boolean, nullable=False),
        sa.Column("disposition", sa.String(24), nullable=False),
        sa.Column("signed_body", JSONB, nullable=False),
        sa.Column("signature", sa.LargeBinary(128), nullable=False),
        sa.Column("measured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id", "target_id", "published_revision"],
            [
                "release_publications.org_id", "release_publications.target_id",
                "release_publications.published_revision",
            ],
        ),
        sa.CheckConstraint("published_revision > 0", name="observation_revision"),
        sa.CheckConstraint("attempt_sequence > 0", name="observation_attempt"),
        sa.CheckConstraint(
            "http_status BETWEEN 100 AND 599", name="observation_http_status"
        ),
        sa.CheckConstraint(
            "disposition IN ('MATCH','CURRENT_MISMATCH','COVERAGE_GAP','HISTORICAL')",
            name="observation_disposition",
        ),
        sa.CheckConstraint(
            "octet_length(expected_sha256) = 32", name="observation_expected_hash"
        ),
        sa.CheckConstraint(
            "octet_length(observed_sha256) = 32", name="observation_observed_hash"
        ),
        sa.CheckConstraint(
            "octet_length(expected_profile_sha256) = 32",
            name="observation_expected_profile",
        ),
        sa.CheckConstraint(
            "octet_length(observed_profile_sha256) = 32",
            name="observation_observed_profile",
        ),
        sa.CheckConstraint(
            "octet_length(signature) BETWEEN 8 AND 128", name="observation_signature_size"
        ),
    )
    op.create_index(
        "ix_observation_timeline", "release_observations",
        ["org_id", "target_id", "published_revision", "measured_at"],
    )
    op.execute("ALTER TABLE release_observations ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE release_observations FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_scope ON release_observations "
        "USING (org_id = nullif(current_setting('aegentra.org_id', true), '')::uuid) "
        "WITH CHECK (org_id = nullif(current_setting('aegentra.org_id', true), '')::uuid)"
    )


def downgrade() -> None:
    op.drop_index("ix_observation_timeline", table_name="release_observations")
    op.drop_table("release_observations")
