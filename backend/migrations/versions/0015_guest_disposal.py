"""Durable physical disposal intent before any EBS DeleteVolume.

Revision ID: 0015_guest_disposal
Revises: 0014_incident_states
"""
from alembic import op


revision = "0015_guest_disposal"
down_revision = "0014_incident_states"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint("guest_attempt_state", "guest_attempts", type_="check")
    op.create_check_constraint(
        "guest_attempt_state", "guest_attempts",
        "state IN ('RESERVED','VOLUMES_RECORDED','INSTANCE_RECORDED',"
        "'DETACHED_VERIFIED','DELETE_REQUESTED','QUARANTINED','DISPOSED')",
    )


def downgrade() -> None:
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM guest_attempts
                WHERE state = 'DELETE_REQUESTED'
            ) THEN
                RAISE EXCEPTION 'reconcile pending physical disposal before downgrade';
            END IF;
        END
        $$;
    """)
    op.drop_constraint("guest_attempt_state", "guest_attempts", type_="check")
    op.create_check_constraint(
        "guest_attempt_state", "guest_attempts",
        "state IN ('RESERVED','VOLUMES_RECORDED','INSTANCE_RECORDED',"
        "'DETACHED_VERIFIED','QUARANTINED','DISPOSED')",
    )
