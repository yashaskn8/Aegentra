"""Pre-enrolled OIDC identities and server-side browser sessions.

Revision ID: 0002_identity
Revises: 0001_foundation
"""
from alembic import op
import sqlalchemy as sa


revision = "0002_identity"
down_revision = "0001_foundation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "identities",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("org_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("issuer", sa.String(256), nullable=False),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("active", sa.Boolean, nullable=False),
        sa.Column("membership_version", sa.Integer, nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.UniqueConstraint("org_id", "id", name="uq_identity_org_id"),
        sa.UniqueConstraint("issuer", "subject", name="uq_identity_issuer_subject"),
        sa.CheckConstraint("role IN ('ADMIN', 'EDITOR', 'ANALYST', 'VIEWER')", name="identity_role"),
        sa.CheckConstraint("membership_version > 0", name="identity_membership_version"),
    )
    op.create_table(
        "login_challenges",
        sa.Column("state_hash", sa.LargeBinary(32), primary_key=True),
        sa.Column("browser_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("verifier", sa.String(128), nullable=False),
        sa.Column("nonce", sa.String(128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("octet_length(state_hash) = 32", name="login_state_hash_length"),
        sa.CheckConstraint("octet_length(browser_hash) = 32", name="login_browser_hash_length"),
    )
    op.create_table(
        "browser_sessions",
        sa.Column("token_hash", sa.LargeBinary(32), primary_key=True),
        sa.Column("identity_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("org_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idle_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id", "identity_id"], ["identities.org_id", "identities.id"]
        ),
        sa.CheckConstraint("octet_length(token_hash) = 32", name="session_token_hash_length"),
    )
    op.create_index("ix_login_challenges_expires", "login_challenges", ["expires_at"])
    op.create_index("ix_browser_sessions_identity", "browser_sessions", ["identity_id"])
    # These tables are internal authentication primitives. Identity enrollment
    # and session administration use separate least-privilege DB permissions.


def downgrade() -> None:
    op.drop_index("ix_browser_sessions_identity", table_name="browser_sessions")
    op.drop_index("ix_login_challenges_expires", table_name="login_challenges")
    op.drop_table("browser_sessions")
    op.drop_table("login_challenges")
    op.drop_table("identities")
