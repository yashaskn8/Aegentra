"""Retain canonical audit payload bytes for independently checkable events.

Revision ID: 0017_audit_payload
Revises: 0016_incident_containment

Existing records cannot be backfilled from hashes. Their NULL payloads
remain explicitly ineligible for payload-complete reconciliation.
"""
from alembic import op
import sqlalchemy as sa


revision = "0017_audit_payload"
down_revision = "0016_incident_containment"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_entries", sa.Column("payload_bytes", sa.LargeBinary(), nullable=True))
    op.create_check_constraint(
        "audit_payload_bound", "audit_entries",
        "payload_bytes IS NULL OR octet_length(payload_bytes) BETWEEN 1 AND 65536",
    )


def downgrade() -> None:
    op.drop_constraint("audit_payload_bound", "audit_entries", type_="check")
    op.drop_column("audit_entries", "payload_bytes")
