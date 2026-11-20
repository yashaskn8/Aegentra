"""Bind every newly published revision to a fixed two-resource identity.

Revision ID: 0013_fixed_bundle
Revises: 0012_outbox_delivery
"""
from alembic import op
import sqlalchemy as sa

revision = "0013_fixed_bundle"
down_revision = "0012_outbox_delivery"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Historical fixture publications cannot be upgraded into qualified
    # bundles without fresh source proof. Null means never servable.
    op.add_column(
        "release_publications",
        sa.Column("fixed_bundle_sha256", sa.LargeBinary(32), nullable=True),
    )
    op.create_check_constraint(
        "release_publication_bundle_hash", "release_publications",
        "fixed_bundle_sha256 IS NULL OR octet_length(fixed_bundle_sha256) = 32",
    )


def downgrade() -> None:
    op.drop_constraint(
        "release_publication_bundle_hash", "release_publications",
    )
    op.drop_column("release_publications", "fixed_bundle_sha256")
