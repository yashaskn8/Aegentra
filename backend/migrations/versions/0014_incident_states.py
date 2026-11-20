"""Expand incident case state without inventing containment success.

Revision ID: 0014_incident_states
Revises: 0013_fixed_bundle
"""
from alembic import op
import sqlalchemy as sa


revision = "0014_incident_states"
down_revision = "0013_fixed_bundle"
branch_labels = None
depends_on = None

_ALLOWED = (
    "status IN ('OPEN','TRIAGED','CONTAINMENT_REQUESTED',"
    "'CONTAINED','RECOVERING','CLOSED')"
)


def upgrade() -> None:
    op.alter_column(
        "investigation_cases", "status",
        existing_type=sa.String(12), type_=sa.String(24),
        existing_nullable=False,
    )
    op.drop_constraint("case_status", "investigation_cases", type_="check")
    op.create_check_constraint("case_status", "investigation_cases", _ALLOWED)


def downgrade() -> None:
    # Refuse a downgrade rather than silently losing an active incident state.
    op.execute("""
        DO $
        BEGIN
            IF EXISTS (
                SELECT 1 FROM investigation_cases
                WHERE status NOT IN ('OPEN', 'CLOSED')
            ) THEN
                RAISE EXCEPTION 'incident state requires explicit recovery before downgrade';
            END IF;
        END
        $;
    """)
    op.drop_constraint("case_status", "investigation_cases", type_="check")
    op.create_check_constraint(
        "case_status", "investigation_cases",
        "status IN ('OPEN','CLOSED')",
    )
    op.alter_column(
        "investigation_cases", "status",
        existing_type=sa.String(24), type_=sa.String(12),
        existing_nullable=False,
    )
