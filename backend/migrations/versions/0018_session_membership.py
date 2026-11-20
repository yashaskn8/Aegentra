"""Invalidate browser sessions across identity membership transitions.

Revision ID: 0018_session_membership
Revises: 0017_audit_payload

Previously issued browser sessions lack a version and fail authentication.
"""
from alembic import op
import sqlalchemy as sa


revision = "0018_session_membership"
down_revision = "0017_audit_payload"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "browser_sessions",
        sa.Column("membership_version", sa.Integer(), nullable=True),
    )
    op.create_check_constraint(
        "session_membership_version", "browser_sessions",
        "membership_version IS NULL OR membership_version > 0",
    )
    op.execute("""
        CREATE FUNCTION aegentra_advance_membership_version()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.active IS DISTINCT FROM OLD.active
               OR NEW.role IS DISTINCT FROM OLD.role
               OR NEW.issuer IS DISTINCT FROM OLD.issuer
               OR NEW.subject IS DISTINCT FROM OLD.subject
               OR NEW.org_id IS DISTINCT FROM OLD.org_id THEN
                IF OLD.membership_version >= 2147483647 THEN
                    RAISE EXCEPTION 'identity membership version exhausted';
                END IF;
                NEW.membership_version := GREATEST(
                    NEW.membership_version, OLD.membership_version + 1
                );
            ELSIF NEW.membership_version < OLD.membership_version THEN
                RAISE EXCEPTION 'identity membership version cannot decrease';
            END IF;
            RETURN NEW;
        END
        $$;
    """)
    op.execute("""
        CREATE TRIGGER identity_membership_version_guard
        BEFORE UPDATE OF active, role, issuer, subject, org_id, membership_version
        ON identities FOR EACH ROW
        EXECUTE FUNCTION aegentra_advance_membership_version();
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER identity_membership_version_guard ON identities")
    op.execute("DROP FUNCTION aegentra_advance_membership_version()")
    op.drop_constraint("session_membership_version", "browser_sessions", type_="check")
    op.drop_column("browser_sessions", "membership_version")
