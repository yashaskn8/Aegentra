"""Protect physical guest pins and valid state transitions at the DB boundary.

Revision ID: 0020_guest_pin_guard
Revises: 0019_guest_ami_pin
"""
from alembic import op


revision = "0020_guest_pin_guard"
down_revision = "0019_guest_ami_pin"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE FUNCTION aegentra_guard_guest_pin()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF ROW(
                NEW.org_id, NEW.job_id, NEW.generation, NEW.nonce_sha256,
                NEW.input_sha256, NEW.toolchain_sha256, NEW.ami_id,
                NEW.account_id, NEW.availability_zone, NEW.subnet_id,
                NEW.security_group_id, NEW.kms_key_arn, NEW.created_at
            ) IS DISTINCT FROM ROW(
                OLD.org_id, OLD.job_id, OLD.generation, OLD.nonce_sha256,
                OLD.input_sha256, OLD.toolchain_sha256, OLD.ami_id,
                OLD.account_id, OLD.availability_zone, OLD.subnet_id,
                OLD.security_group_id, OLD.kms_key_arn, OLD.created_at
            ) THEN
                RAISE EXCEPTION 'guest physical pin immutable';
            END IF;
            IF NEW.updated_at < OLD.updated_at THEN
                RAISE EXCEPTION 'guest custody clock cannot move backwards';
            END IF;
            IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
                (OLD.state = 'RESERVED'
                 AND NEW.state = 'VOLUMES_RECORDED') OR
                (OLD.state = 'VOLUMES_RECORDED'
                 AND NEW.state = 'INSTANCE_RECORDED') OR
                (OLD.state = 'INSTANCE_RECORDED'
                 AND NEW.state = 'DETACHED_VERIFIED') OR
                (OLD.state = 'DETACHED_VERIFIED'
                 AND NEW.state = 'DELETE_REQUESTED') OR
                (OLD.state = 'DELETE_REQUESTED'
                 AND NEW.state = 'DISPOSED') OR
                (OLD.state NOT IN ('QUARANTINED','DISPOSED')
                 AND NEW.state = 'QUARANTINED')
            ) THEN
                RAISE EXCEPTION 'guest custody state transition denied';
            END IF;
            RETURN NEW;
        END
        $$;
    """)
    op.execute("""
        CREATE TRIGGER guest_physical_pin_guard
        BEFORE UPDATE ON guest_attempts
        FOR EACH ROW
        EXECUTE FUNCTION aegentra_guard_guest_pin();
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER guest_physical_pin_guard ON guest_attempts")
    op.execute("DROP FUNCTION aegentra_guard_guest_pin()")
