"""Atomic audit stream, outbox and idempotent request records.

Revision ID: 0003_audit
Revises: 0002_identity
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "0003_audit"
down_revision = "0002_identity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_streams",
        sa.Column("org_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("stream", sa.String(32), primary_key=True),
        sa.Column("sequence", sa.BigInteger, nullable=False),
        sa.Column("head_hash", sa.LargeBinary(32), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.CheckConstraint("octet_length(head_hash) = 32", name="audit_head_length"),
    )
    op.create_table(
        "audit_entries",
        sa.Column("org_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("stream", sa.String(32), primary_key=True),
        sa.Column("sequence", sa.BigInteger, primary_key=True),
        sa.Column("actor_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("previous_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("event_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("body_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id", "stream"], ["audit_streams.org_id", "audit_streams.stream"]),
        sa.CheckConstraint("octet_length(previous_hash) = 32", name="audit_prev_length"),
        sa.CheckConstraint("octet_length(event_hash) = 32", name="audit_event_length"),
        sa.CheckConstraint("octet_length(body_hash) = 32", name="audit_body_length"),
    )
    op.create_table(
        "outbox_events",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("org_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("stream", sa.String(32), nullable=False),
        sa.Column("sequence", sa.BigInteger, nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(
            ["org_id", "stream", "sequence"],
            ["audit_entries.org_id", "audit_entries.stream", "audit_entries.sequence"],
        ),
        sa.UniqueConstraint("org_id", "stream", "sequence", name="uq_outbox_event"),
    )
    op.create_index("ix_outbox_unsent", "outbox_events", ["created_at"],
                    postgresql_where=sa.text("delivered_at IS NULL"))
    op.create_table(
        "idempotency_requests",
        sa.Column("org_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("identity_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("route", sa.String(80), primary_key=True),
        sa.Column("key", sa.String(128), primary_key=True),
        sa.Column("request_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("response", JSONB, nullable=False),
        sa.Column("status", sa.Integer, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id", "identity_id"], ["identities.org_id", "identities.id"]),
        sa.CheckConstraint("octet_length(request_hash) = 32", name="idempotency_hash_length"),
    )

    for table in ("audit_streams", "audit_entries", "outbox_events", "idempotency_requests"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_scope ON {table} "
            "USING (org_id = nullif(current_setting('aegentra.org_id', true), '')::uuid) "
            "WITH CHECK (org_id = nullif(current_setting('aegentra.org_id', true), '')::uuid)"
        )


def downgrade() -> None:
    op.drop_table("idempotency_requests")
    op.drop_index("ix_outbox_unsent", table_name="outbox_events")
    op.drop_table("outbox_events")
    op.drop_table("audit_entries")
    op.drop_table("audit_streams")
