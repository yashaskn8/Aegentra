"""Release governance guards, consumed grants and immutable selections.

Revision ID: 0009_release
Revises: 0008_scan_receipts
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "0009_release"
down_revision = "0008_scan_receipts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "release_org_guards",
        sa.Column("org_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("incarnation", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("epoch", sa.BigInteger, nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.CheckConstraint("epoch > 0", name="release_org_epoch_positive"),
    )
    op.create_table(
        "release_targets",
        sa.Column("org_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("asset_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("destination_host", sa.String(253), nullable=False),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column("guard", sa.String(24), nullable=False),
        sa.Column("epoch", sa.BigInteger, nullable=False),
        sa.Column("next_attempt_sequence", sa.BigInteger, nullable=False),
        sa.Column("published_revision", sa.BigInteger, nullable=False),
        sa.Column("published_attempt_sequence", sa.BigInteger),
        sa.ForeignKeyConstraint(["org_id"], ["release_org_guards.org_id"]),
        sa.ForeignKeyConstraint(["org_id", "asset_id"], ["assets.org_id", "assets.id"]),
        sa.CheckConstraint("mode IN ('SHADOW','ENFORCED','RETIRED')", name="release_target_mode"),
        sa.CheckConstraint(
            "guard IN ('ACTIVE','HOLD_PROMOTION','STOP_SERVING')",
            name="release_target_guard",
        ),
        sa.CheckConstraint("epoch > 0", name="release_target_epoch_positive"),
        sa.CheckConstraint("next_attempt_sequence >= 0", name="release_attempt_sequence_nonnegative"),
        sa.CheckConstraint("published_revision >= 0", name="release_published_revision_nonnegative"),
    )
    op.create_table(
        "release_grants",
        sa.Column("org_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("target_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("nonce_hash", sa.LargeBinary(32), primary_key=True),
        sa.Column("subject_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("subject_body", JSONB, nullable=False),
        sa.Column("approval_set_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("incarnation", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("org_epoch", sa.BigInteger, nullable=False),
        sa.Column("target_epoch", sa.BigInteger, nullable=False),
        sa.Column("expected_prior_revision", sa.BigInteger, nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("selection_sequence", sa.BigInteger),
        sa.ForeignKeyConstraint(
            ["org_id", "target_id"], ["release_targets.org_id", "release_targets.id"]
        ),
        sa.CheckConstraint("octet_length(nonce_hash) = 32", name="release_grant_nonce_length"),
        sa.CheckConstraint("octet_length(subject_sha256) = 32", name="release_grant_subject_length"),
        sa.CheckConstraint("octet_length(approval_set_sha256) = 32", name="release_grant_approval_length"),
        sa.CheckConstraint(
            "status IN ('GRANTED','REDEEMED','CANCELED','EXPIRED')",
            name="release_grant_status",
        ),
    )
    op.create_table(
        "release_selections",
        sa.Column("org_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("target_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("attempt_sequence", sa.BigInteger, primary_key=True),
        sa.Column("grant_nonce_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("subject_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("staging_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("prior_published_revision", sa.BigInteger, nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("witness_version_id", sa.String(256)),
        sa.Column("witness_sha256", sa.LargeBinary(32)),
        sa.ForeignKeyConstraint(
            ["org_id", "target_id", "grant_nonce_hash"],
            ["release_grants.org_id", "release_grants.target_id", "release_grants.nonce_hash"],
        ),
        sa.UniqueConstraint(
            "org_id", "target_id", "grant_nonce_hash",
            name="uq_release_selection_grant",
        ),
        sa.CheckConstraint("attempt_sequence > 0", name="release_attempt_positive"),
        sa.CheckConstraint("octet_length(subject_sha256) = 32", name="release_selection_subject_length"),
        sa.CheckConstraint("octet_length(staging_sha256) = 32", name="release_selection_staging_length"),
        sa.CheckConstraint(
            "witness_sha256 IS NULL OR octet_length(witness_sha256) = 32",
            name="release_selection_witness_length",
        ),
        sa.CheckConstraint(
            "state IN ('SELECTED_UNWITNESSED','WITNESSED','PUBLISHED','CANCELED','EXPIRED')",
            name="release_selection_state",
        ),
    )
    op.create_table(
        "release_publications",
        sa.Column("org_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("target_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("published_revision", sa.BigInteger, primary_key=True),
        sa.Column("attempt_sequence", sa.BigInteger, nullable=False),
        sa.Column("witness_version_id", sa.String(256), nullable=False),
        sa.Column("witness_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("representation_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("delivery_profile_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id", "target_id", "attempt_sequence"],
            ["release_selections.org_id", "release_selections.target_id", "release_selections.attempt_sequence"],
        ),
        sa.UniqueConstraint(
            "org_id", "target_id", "attempt_sequence",
            name="uq_publication_for_selection",
        ),
        sa.CheckConstraint("published_revision > 0", name="release_revision_positive"),
        sa.CheckConstraint("octet_length(witness_sha256) = 32", name="release_publication_witness_length"),
        sa.CheckConstraint("octet_length(representation_sha256) = 32", name="release_publication_bytes_length"),
        sa.CheckConstraint("octet_length(delivery_profile_sha256) = 32", name="release_publication_profile_length"),
    )

    op.create_table(
        "release_endorsements",
        sa.Column("org_id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("challenge_sha256", sa.LargeBinary(32), primary_key=True),
        sa.Column("subject_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("target_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("person_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("key_id", sa.String(128), nullable=False),
        sa.Column("custody_group", sa.String(64), nullable=False),
        sa.Column("enrollment_generation", sa.BigInteger, nullable=False),
        sa.Column("signed_body", JSONB, nullable=False),
        sa.Column("signature", sa.LargeBinary(64), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id", "target_id"], ["release_targets.org_id", "release_targets.id"]
        ),
        sa.UniqueConstraint("org_id", "subject_sha256", "person_id", name="uq_release_endorsement_person"),
        sa.UniqueConstraint("org_id", "subject_sha256", "key_id", name="uq_release_endorsement_key"),
        sa.CheckConstraint("octet_length(challenge_sha256) = 32", name="release_endorsement_nonce_length"),
        sa.CheckConstraint("octet_length(subject_sha256) = 32", name="release_endorsement_subject_length"),
        sa.CheckConstraint("octet_length(signature) = 64", name="release_endorsement_signature_length"),
    )

    for table in (
        "release_org_guards", "release_targets", "release_endorsements", "release_grants",
        "release_selections", "release_publications",
    ):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_scope ON {table} "
            "USING (org_id = nullif(current_setting('aegentra.org_id', true), '')::uuid) "
            "WITH CHECK (org_id = nullif(current_setting('aegentra.org_id', true), '')::uuid)"
        )


def downgrade() -> None:
    for table in (
        "release_publications", "release_selections", "release_endorsements", "release_grants",
        "release_targets", "release_org_guards",
    ):
        op.drop_table(table)
