"""Durable native EBS attachment and EC2 termination intents.

Revision ID: 0022_guest_physical_operations
Revises: 0021_guest_create_intents
"""
from alembic import op
import sqlalchemy as sa


revision = "0022_guest_physical_operations"
down_revision = "0021_guest_create_intents"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "guest_physical_operations",
        sa.Column("org_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("job_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("generation", sa.BigInteger, primary_key=True),
        sa.Column("kind", sa.String(16), primary_key=True),
        sa.Column("instance_id", sa.String(40), nullable=False),
        sa.Column("volume_id", sa.String(40), nullable=True),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id", "job_id", "generation"],
            ["guest_attempts.org_id", "guest_attempts.job_id", "guest_attempts.generation"],
        ),
        sa.CheckConstraint(
            "kind IN ('ATTACH_INPUT','ATTACH_OUTPUT','TERMINATE')",
            name="guest_physical_kind",
        ),
        sa.CheckConstraint(
            "state IN ('PREPARED','VERIFIED','REQUESTED','UNKNOWN')",
            name="guest_physical_state",
        ),
        sa.CheckConstraint(
            "(kind = 'TERMINATE' AND volume_id IS NULL) OR "
            "(kind IN ('ATTACH_INPUT','ATTACH_OUTPUT') AND volume_id IS NOT NULL)",
            name="guest_physical_volume_scope",
        ),
        sa.CheckConstraint(
            "(state = 'VERIFIED' AND kind <> 'TERMINATE') OR "
            "(state = 'REQUESTED' AND kind = 'TERMINATE') OR "
            "state IN ('PREPARED','UNKNOWN')",
            name="guest_physical_outcome_kind",
        ),
    )
    op.execute("ALTER TABLE guest_physical_operations ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE guest_physical_operations FORCE ROW LEVEL SECURITY")
    op.execute("""
        CREATE POLICY tenant_scope ON guest_physical_operations
        USING (org_id = nullif(current_setting('aegentra.org_id', true), '')::uuid)
        WITH CHECK (org_id = nullif(current_setting('aegentra.org_id', true), '')::uuid)
    """)
    op.execute("""
        CREATE FUNCTION aegentra_guard_guest_operation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF ROW(
                NEW.org_id, NEW.job_id, NEW.generation, NEW.kind,
                NEW.instance_id, NEW.volume_id, NEW.created_at
            ) IS DISTINCT FROM ROW(
                OLD.org_id, OLD.job_id, OLD.generation, OLD.kind,
                OLD.instance_id, OLD.volume_id, OLD.created_at
            ) THEN
                RAISE EXCEPTION 'guest physical operation identity immutable';
            END IF;
            IF OLD.state <> 'PREPARED' OR NEW.updated_at < OLD.updated_at
                OR NOT (
                    (NEW.state = 'UNKNOWN')
                    OR (OLD.kind = 'TERMINATE' AND NEW.state = 'REQUESTED')
                    OR (OLD.kind <> 'TERMINATE' AND NEW.state = 'VERIFIED')
                ) THEN
                RAISE EXCEPTION 'guest physical operation outcome is terminal';
            END IF;
            RETURN NEW;
        END
        $$;
    """)
    op.execute("""
        CREATE TRIGGER guest_physical_operation_guard
        BEFORE UPDATE ON guest_physical_operations
        FOR EACH ROW EXECUTE FUNCTION aegentra_guard_guest_operation();
    """)


def downgrade() -> None:
    op.execute("""
        DO $$ BEGIN
            IF EXISTS (SELECT 1 FROM guest_physical_operations) THEN
                RAISE EXCEPTION 'reconcile physical AWS operations before downgrade';
            END IF;
        END $$;
    """)
    op.execute("DROP TRIGGER guest_physical_operation_guard ON guest_physical_operations")
    op.execute("DROP FUNCTION aegentra_guard_guest_operation()")
    op.drop_table("guest_physical_operations")
