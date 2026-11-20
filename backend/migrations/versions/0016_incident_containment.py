"""Separate privileged incident-role containment and immutable proof ref.

Revision ID: 0016_incident_containment
Revises: 0015_guest_disposal
"""
from alembic import op
import sqlalchemy as sa


revision = "0016_incident_containment"
down_revision = "0015_guest_disposal"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "incident_containment_receipts",
        sa.Column("org_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("case_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("veto_generation", sa.BigInteger, primary_key=True),
        sa.Column("target_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("incarnation", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("root_version_id", sa.String(256), nullable=False),
        sa.Column("archive_version_id", sa.String(256), nullable=False),
        sa.Column("archive_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("gateway_count", sa.Integer, nullable=False),
        sa.Column("recorded_by", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id", "case_id"],
            ["investigation_cases.org_id", "investigation_cases.id"],
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "target_id"],
            ["release_targets.org_id", "release_targets.id"],
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "recorded_by"],
            ["identities.org_id", "identities.id"],
        ),
        sa.CheckConstraint("veto_generation > 0", name="incident_veto_generation"),
        sa.CheckConstraint(
            "gateway_count BETWEEN 1 AND 256", name="incident_gateway_count",
        ),
        sa.CheckConstraint(
            "octet_length(archive_sha256) = 32", name="incident_archive_digest",
        ),
    )
    op.execute("ALTER TABLE incident_containment_receipts ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE incident_containment_receipts FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_scope ON incident_containment_receipts "
        "USING (org_id = nullif(current_setting('aegentra.org_id', true), '')::uuid) "
        "WITH CHECK (org_id = nullif(current_setting('aegentra.org_id', true), '')::uuid)"
    )
    op.execute("""
        CREATE FUNCTION aegentra_incident_privileged_transition()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.status IS DISTINCT FROM OLD.status
               AND NEW.status IN ('CONTAINED','RECOVERING','CLOSED')
               AND current_user <> 'aegentra_incident' THEN
                RAISE EXCEPTION
                    'independent incident custody role required for privileged state';
            END IF;
            RETURN NEW;
        END
        $$;
    """)
    op.execute("""
        CREATE TRIGGER incident_privileged_state_guard
        BEFORE UPDATE OF status ON investigation_cases
        FOR EACH ROW
        EXECUTE FUNCTION aegentra_incident_privileged_transition();
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER incident_privileged_state_guard ON investigation_cases")
    op.execute("DROP FUNCTION aegentra_incident_privileged_transition()")
    op.drop_table("incident_containment_receipts")
