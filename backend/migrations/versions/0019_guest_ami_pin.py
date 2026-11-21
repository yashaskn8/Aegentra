"""Pin native EC2 AMI identity for each physical scan attempt.

Revision ID: 0019_guest_ami_pin
Revises: 0018_session_membership

Existing attempts intentionally keep NULL and fail trusted validation.
No AMI is retroactively invented or backfilled from untrusted tags.
"""
from alembic import op
import sqlalchemy as sa


revision = "0019_guest_ami_pin"
down_revision = "0018_session_membership"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "guest_attempts",
        sa.Column("ami_id", sa.String(21), nullable=True),
    )
    op.create_check_constraint(
        "guest_ami_pin", "guest_attempts",
        "ami_id IS NULL OR ami_id ~ '^ami-[0-9a-f]{8,17}$'",
    )


def downgrade() -> None:
    op.drop_constraint("guest_ami_pin", "guest_attempts", type_="check")
    op.drop_column("guest_attempts", "ami_id")
