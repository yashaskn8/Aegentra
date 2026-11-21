"""Durable, non-reusable EC2 resource creation intents before AWS calls.

Revision ID: 0021_guest_create_intents
Revises: 0020_guest_pin_guard
"""
from alembic import op
import sqlalchemy as sa


revision = "0021_guest_create_intents"
down_revision = "0020_guest_pin_guard"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "guest_create_intents",
        sa.Column("org_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("job_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("generation", sa.BigInteger, primary_key=True),
        sa.Column("kind", sa.String(16), primary_key=True),
        sa.Column("plan_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("token_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("resource_id", sa.String(40), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id", "job_id", "generation"],
            ["guest_attempts.org_id", "guest_attempts.job_id", "guest_attempts.generation"],
        ),
        sa.UniqueConstraint("token_sha256", name="uq_guest_create_token"),
        sa.CheckConstraint(
            "kind IN ('INPUT_EBS','OUTPUT_EBS','INSTANCE')", name="guest_create_kind",
        ),
        sa.CheckConstraint(
            "octet_length(plan_sha256) = 32", name="guest_create_plan_hash",
        ),
        sa.CheckConstraint(
            "octet_length(token_sha256) = 32", name="guest_create_token_hash",
        ),
        sa.CheckConstraint(
            "status IN ('PREPARED','RECORDED','UNKNOWN')", name="guest_create_status",
        ),
        sa.CheckConstraint(
            "(status = 'RECORDED' AND resource_id IS NOT NULL) OR "
            "(status <> 'RECORDED' AND resource_id IS NULL)",
            name="guest_create_resource_state",
        ),
    )
    op.execute("ALTER TABLE guest_create_intents ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE guest_create_intents FORCE ROW LEVEL SECURITY")
    op.execute("""
        CREATE POLICY tenant_scope ON guest_create_intents
        USING (org_id = nullif(current_setting('aegentra.org_id', true), '')::uuid)
        WITH CHECK (org_id = nullif(current_setting('aegentra.org_id', true), '')::uuid)
    """)
    op.execute("""
        CREATE FUNCTION aegentra_guard_guest_create_intent()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF ROW(
                NEW.org_id, NEW.job_id, NEW.generation, NEW.kind,
                NEW.plan_sha256, NEW.token_sha256, NEW.created_at
            ) IS DISTINCT FROM ROW(
                OLD.org_id, OLD.job_id, OLD.generation, OLD.kind,
                OLD.plan_sha256, OLD.token_sha256, OLD.created_at
            ) THEN
                RAISE EXCEPTION 'guest creation intent immutable';
            END IF;
            IF OLD.status <> 'PREPARED'
               OR NEW.status NOT IN ('RECORDED','UNKNOWN')
               OR NEW.updated_at < OLD.updated_at THEN
                RAISE EXCEPTION 'guest creation outcome cannot be rewritten';
            END IF;
            RETURN NEW;
        END
        $$;
    """)
    op.execute("""
        CREATE TRIGGER guest_creation_intent_guard
        BEFORE UPDATE ON guest_create_intents
        FOR EACH ROW
        EXECUTE FUNCTION aegentra_guard_guest_create_intent();
    """)


def downgrade() -> None:
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM guest_create_intents) THEN
                RAISE EXCEPTION 'reconcile native AWS creation intents before downgrade';
            END IF;
        END
        $$;
    """)
    op.execute("DROP TRIGGER guest_creation_intent_guard ON guest_create_intents")
    op.execute("DROP FUNCTION aegentra_guard_guest_create_intent()")
    op.drop_table("guest_create_intents")
