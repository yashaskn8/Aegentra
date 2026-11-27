"""Index authorized case evidence in cursor order.

Revision ID: 0023_case_evidence_page
Revises: 0022_guest_physical_operations
"""
from alembic import op


revision = "0023_case_evidence_page"
down_revision = "0022_guest_physical_operations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_case_evidence_page",
        "case_evidence",
        ["org_id", "asset_id", "case_id", "linked_at", "evidence_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_case_evidence_page", table_name="case_evidence")
