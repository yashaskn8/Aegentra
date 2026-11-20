"""Bounded native outbox dispatch claims and retry state.

Revision ID: 0012_outbox_delivery
Revises: 0011_observations
"""
from alembic import op
import sqlalchemy as sa


revision = "0012_outbox_delivery"
down_revision = "0011_observations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "outbox_events", sa.Column(
            "attempts", sa.Integer, nullable=False, server_default="0",
        ),
    )
    op.add_column(
        "outbox_events", sa.Column(
            "lease_generation", sa.BigInteger, nullable=False, server_default="0",
        ),
    )
    for field in ("lease_expires", "next_attempt_at", "abandoned_at"):
        op.add_column(
            "outbox_events", sa.Column(field, sa.DateTime(timezone=True)),
        )
    op.add_column("outbox_events", sa.Column("lease_nonce_hash", sa.LargeBinary(32)))
    op.add_column("outbox_events", sa.Column("last_error_code", sa.String(48)))
    op.add_column("outbox_events", sa.Column("delivery_reference", sa.String(128)))
    op.create_check_constraint(
        "outbox_attempt_budget", "outbox_events", "attempts BETWEEN 0 AND 10",
    )
    op.create_check_constraint(
        "outbox_generation_nonnegative", "outbox_events",
        "lease_generation >= 0",
    )
    op.create_check_constraint(
        "outbox_lease_digest_length", "outbox_events",
        "lease_nonce_hash IS NULL OR octet_length(lease_nonce_hash) = 32",
    )
    op.create_index(
        "ix_outbox_retry", "outbox_events",
        ["org_id", "next_attempt_at", "created_at"],
        postgresql_where=sa.text(
            "delivered_at IS NULL AND abandoned_at IS NULL"
        ),
    )


def downgrade() -> None:
    op.drop_index("ix_outbox_retry", table_name="outbox_events")
    for name in (
        "outbox_lease_digest_length", "outbox_generation_nonnegative",
        "outbox_attempt_budget",
    ):
        op.drop_constraint(name, "outbox_events")
    for field in (
        "delivery_reference", "last_error_code", "abandoned_at",
        "next_attempt_at", "lease_nonce_hash", "lease_expires",
        "lease_generation", "attempts",
    ):
        op.drop_column("outbox_events", field)
