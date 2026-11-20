"""Initial PostgreSQL schema. No production database connection is initialized here."""
from __future__ import annotations

from uuid import UUID, uuid4
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Integer

from sqlalchemy import CheckConstraint, ForeignKeyConstraint, LargeBinary, String, Uuid, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.dialects.postgresql import JSONB


class Base(DeclarativeBase):
    pass


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    slug: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)


class Asset(Base):
    __tablename__ = "assets"

    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    slug: Mapped[str] = mapped_column(String(80), nullable=False)
    criticality: Mapped[str] = mapped_column(String(8), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        CheckConstraint("criticality IN ('LOW', 'MEDIUM', 'HIGH')", name="asset_criticality"),
        UniqueConstraint("org_id", "slug", name="uq_asset_org_slug"),
    )


class Evidence(Base):
    __tablename__ = "evidence"

    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    asset_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(["org_id", "asset_id"], ["assets.org_id", "assets.id"]),
        CheckConstraint("octet_length(digest) = 32", name="evidence_digest_length"),
        UniqueConstraint("org_id", "asset_id", "id", name="uq_evidence_org_asset_id"),
    )


class Identity(Base):
    """Pre-enrolled identity: IdP claims never grant a role by themselves."""

    __tablename__ = "identities"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    issuer: Mapped[str] = mapped_column(String(256), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    membership_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (
        ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        UniqueConstraint("org_id", "id", name="uq_identity_org_id"),
        UniqueConstraint("issuer", "subject", name="uq_identity_issuer_subject"),
        CheckConstraint("role IN ('ADMIN', 'EDITOR', 'ANALYST', 'VIEWER')", name="identity_role"),
        CheckConstraint("membership_version > 0", name="identity_membership_version"),
    )


class LoginChallenge(Base):
    __tablename__ = "login_challenges"

    state_hash: Mapped[bytes] = mapped_column(LargeBinary(32), primary_key=True)
    browser_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    verifier: Mapped[str] = mapped_column(String(128), nullable=False)
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint("octet_length(state_hash) = 32", name="login_state_hash_length"),
        CheckConstraint("octet_length(browser_hash) = 32", name="login_browser_hash_length"),
    )


class BrowserSession(Base):
    __tablename__ = "browser_sessions"

    token_hash: Mapped[bytes] = mapped_column(LargeBinary(32), primary_key=True)
    identity_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    idle_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "identity_id"], ["identities.org_id", "identities.id"]
        ),
        CheckConstraint("octet_length(token_hash) = 32", name="session_token_hash_length"),
    )


class AuditStream(Base):
    """Transactional chain head. Independent archive witnessing is a later stage."""

    __tablename__ = "audit_streams"

    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    stream: Mapped[str] = mapped_column(String(32), primary_key=True)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    head_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        CheckConstraint("octet_length(head_hash) = 32", name="audit_head_length"),
    )


class AuditEntry(Base):
    __tablename__ = "audit_entries"

    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    stream: Mapped[str] = mapped_column(String(32), primary_key=True)
    sequence: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    actor_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    event_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    body_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    payload_bytes: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(["org_id", "stream"], ["audit_streams.org_id", "audit_streams.stream"]),
        CheckConstraint("octet_length(previous_hash) = 32", name="audit_prev_length"),
        CheckConstraint("octet_length(event_hash) = 32", name="audit_event_length"),
        CheckConstraint("octet_length(body_hash) = 32", name="audit_body_length"),
        CheckConstraint(
            "payload_bytes IS NULL OR octet_length(payload_bytes) BETWEEN 1 AND 65536",
            name="audit_payload_bound",
        ),
    )


class OutboxEvent(Base):
    __tablename__ = "outbox_events"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    stream: Mapped[str] = mapped_column(String(32), nullable=False)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    lease_generation: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    lease_nonce_hash: Mapped[bytes | None] = mapped_column(LargeBinary(32), nullable=True)
    lease_expires: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    abandoned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error_code: Mapped[str | None] = mapped_column(String(48), nullable=True)
    delivery_reference: Mapped[str | None] = mapped_column(String(128), nullable=True)

    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "stream", "sequence"],
            ["audit_entries.org_id", "audit_entries.stream", "audit_entries.sequence"],
        ),
        UniqueConstraint("org_id", "stream", "sequence", name="uq_outbox_event"),
        CheckConstraint("attempts BETWEEN 0 AND 10", name="outbox_attempt_budget"),
        CheckConstraint("lease_generation >= 0", name="outbox_generation_nonnegative"),
        CheckConstraint(
            "lease_nonce_hash IS NULL OR octet_length(lease_nonce_hash) = 32",
            name="outbox_lease_digest_length",
        ),
    )


class IdempotencyRequest(Base):
    __tablename__ = "idempotency_requests"

    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    identity_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    route: Mapped[str] = mapped_column(String(80), primary_key=True)
    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    request_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    response: Mapped[dict] = mapped_column(JSONB, nullable=False)
    status: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(["org_id", "identity_id"], ["identities.org_id", "identities.id"]),
        CheckConstraint("octet_length(request_hash) = 32", name="idempotency_hash_length"),
    )


class InvestigationCase(Base):
    __tablename__ = "investigation_cases"

    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    asset_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    title: Mapped[str] = mapped_column(String(140), nullable=False)
    created_by: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="OPEN")
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(["org_id", "asset_id"], ["assets.org_id", "assets.id"]),
        ForeignKeyConstraint(["org_id", "created_by"], ["identities.org_id", "identities.id"]),
        UniqueConstraint("org_id", "asset_id", "id", name="uq_case_org_asset_id"),
        CheckConstraint("status IN ('OPEN','TRIAGED','CONTAINMENT_REQUESTED','CONTAINED','RECOVERING','CLOSED')", name="case_status"),
        CheckConstraint("revision > 0", name="case_revision_positive"),
    )


class CaseMembership(Base):
    __tablename__ = "case_memberships"

    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    case_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    identity_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    grant_type: Mapped[str] = mapped_column(String(12), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(["org_id", "case_id"], ["investigation_cases.org_id", "investigation_cases.id"]),
        ForeignKeyConstraint(["org_id", "identity_id"], ["identities.org_id", "identities.id"]),
        CheckConstraint("grant_type IN ('OWNER', 'ANALYST', 'VIEWER')", name="case_grant"),
    )


class CaseEvidence(Base):
    __tablename__ = "case_evidence"

    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    asset_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    case_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    evidence_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    linked_by: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "asset_id", "case_id"],
            ["investigation_cases.org_id", "investigation_cases.asset_id", "investigation_cases.id"],
        ),
        ForeignKeyConstraint(
            ["org_id", "asset_id", "evidence_id"],
            ["evidence.org_id", "evidence.asset_id", "evidence.id"],
        ),
        ForeignKeyConstraint(["org_id", "linked_by"], ["identities.org_id", "identities.id"]),
    )


class StagingUpload(Base):
    """Declared, untrusted staging metadata; never a signed artifact."""

    __tablename__ = "staging_uploads"

    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    asset_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    issued_by: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    content_digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    content_manifest: Mapped[dict] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(["org_id", "asset_id"], ["assets.org_id", "assets.id"]),
        ForeignKeyConstraint(["org_id", "issued_by"], ["identities.org_id", "identities.id"]),
        CheckConstraint("octet_length(content_digest) = 32", name="staging_content_digest_length"),
        CheckConstraint(
            "status IN ('ISSUED', 'AWAITING_VERIFICATION', 'REJECTED')",
            name="staging_status",
        ),
    )


class StagingPart(Base):
    __tablename__ = "staging_parts"

    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    upload_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    part_index: Mapped[int] = mapped_column(Integer, primary_key=True)
    path: Mapped[str] = mapped_column(String(128), nullable=False)
    content_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    byte_length: Mapped[int] = mapped_column(Integer, nullable=False)
    media_type: Mapped[str] = mapped_column(String(64), nullable=False)
    object_key: Mapped[str] = mapped_column(String(256), nullable=False)
    version_id: Mapped[str | None] = mapped_column(String(256), nullable=True)

    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "upload_id"], ["staging_uploads.org_id", "staging_uploads.id"]
        ),
        UniqueConstraint("org_id", "upload_id", "path", name="uq_staging_path"),
        UniqueConstraint("org_id", "upload_id", "object_key", name="uq_staging_key"),
        CheckConstraint("octet_length(content_sha256) = 32", name="staging_part_digest_length"),
        CheckConstraint("byte_length > 0 AND byte_length <= 10485760", name="staging_part_length"),
    )


class ScanJob(Base):
    """Untrusted scan attempt metadata; never a release authorization."""

    __tablename__ = "scan_jobs"

    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    upload_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    attempt_generation: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    lease_nonce: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lease_expires: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempt_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result_sha256: Mapped[bytes | None] = mapped_column(LargeBinary(32), nullable=True)

    __table_args__ = (
        ForeignKeyConstraint(["org_id", "upload_id"], ["staging_uploads.org_id", "staging_uploads.id"]),
        CheckConstraint(
            "status IN ('QUEUED','LEASED','PENDING_TRUSTED_VALIDATION','UNKNOWN')",
            name="scan_job_status",
        ),
        CheckConstraint("attempts BETWEEN 0 AND 3", name="scan_job_attempts"),
        CheckConstraint("attempt_generation >= 0", name="scan_job_generation"),
        CheckConstraint("result_sha256 IS NULL OR octet_length(result_sha256) = 32", name="scan_job_result_hash"),
    )


class GuestAttempt(Base):
    """Bridge-owned physical custody record, separate from API and guest output."""

    __tablename__ = "guest_attempts"

    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    job_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    generation: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    nonce_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    input_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    toolchain_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    account_id: Mapped[str] = mapped_column(String(12), nullable=False)
    availability_zone: Mapped[str] = mapped_column(String(32), nullable=False)
    subnet_id: Mapped[str] = mapped_column(String(40), nullable=False)
    security_group_id: Mapped[str] = mapped_column(String(40), nullable=False)
    kms_key_arn: Mapped[str] = mapped_column(String(256), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(["org_id", "job_id"], ["scan_jobs.org_id", "scan_jobs.id"]),
        CheckConstraint("generation > 0", name="guest_generation_positive"),
        CheckConstraint("octet_length(nonce_sha256) = 32", name="guest_nonce_hash"),
        CheckConstraint("octet_length(input_sha256) = 32", name="guest_input_hash"),
        CheckConstraint("octet_length(toolchain_sha256) = 32", name="guest_toolchain_hash"),
        CheckConstraint(
            "state IN ('RESERVED','VOLUMES_RECORDED','INSTANCE_RECORDED',"
            "'DETACHED_VERIFIED','DELETE_REQUESTED','QUARANTINED','DISPOSED')",
            name="guest_attempt_state",
        ),
    )


class GuestResource(Base):
    """Never-reused AWS physical ID, unique across roles and all organizations."""

    __tablename__ = "guest_resources"

    resource_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    job_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    generation: Mapped[int] = mapped_column(BigInteger, nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "job_id", "generation"],
            ["guest_attempts.org_id", "guest_attempts.job_id", "guest_attempts.generation"],
        ),
        UniqueConstraint(
            "org_id", "job_id", "generation", "kind",
            name="uq_guest_resource_per_attempt_kind",
        ),
        CheckConstraint(
            "kind IN ('INPUT_EBS','OUTPUT_EBS','INSTANCE')", name="guest_resource_kind",
        ),
    )


class ScanReceipt(Base):
    """Validator-issued advisory receipt. Not a signed release predicate."""

    __tablename__ = "scan_receipts"

    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    job_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    generation: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    result_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    source_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    toolchain_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    coverage: Mapped[str] = mapped_column(String(16), nullable=False)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False)
    reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "job_id", "generation"],
            ["guest_attempts.org_id", "guest_attempts.job_id", "guest_attempts.generation"],
        ),
        CheckConstraint("octet_length(result_sha256) = 32", name="scan_receipt_result_hash"),
        CheckConstraint("octet_length(source_sha256) = 32", name="scan_receipt_source_hash"),
        CheckConstraint("octet_length(toolchain_sha256) = 32", name="scan_receipt_toolchain_hash"),
        CheckConstraint("status IN ('COMPLETE','INCOMPLETE')", name="scan_receipt_status"),
        CheckConstraint("coverage IN ('VERIFIED','UNKNOWN','UNSUPPORTED')", name="scan_receipt_coverage"),
        CheckConstraint("finding_count BETWEEN 0 AND 2000", name="scan_receipt_finding_count"),
    )


class ReleaseOrgGuard(Base):
    """Single serialized guard for an installation's release-affecting state."""

    __tablename__ = "release_org_guards"

    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    incarnation: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    epoch: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)

    __table_args__ = (
        ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        CheckConstraint("epoch > 0", name="release_org_epoch_positive"),
    )


class ReleaseTarget(Base):
    __tablename__ = "release_targets"

    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    asset_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    destination_host: Mapped[str] = mapped_column(String(253), nullable=False)
    resource_path: Mapped[str | None] = mapped_column(String(160), nullable=True)
    mode: Mapped[str] = mapped_column(String(16), nullable=False, default="SHADOW")
    guard: Mapped[str] = mapped_column(String(24), nullable=False, default="ACTIVE")
    epoch: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)
    next_attempt_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    published_revision: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    published_attempt_sequence: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    origin_bucket: Mapped[str | None] = mapped_column(String(63), nullable=True)
    origin_key_prefix: Mapped[str | None] = mapped_column(String(160), nullable=True)

    __table_args__ = (
        ForeignKeyConstraint(["org_id"], ["release_org_guards.org_id"]),
        ForeignKeyConstraint(["org_id", "asset_id"], ["assets.org_id", "assets.id"]),
        CheckConstraint("mode IN ('SHADOW','ENFORCED','RETIRED')", name="release_target_mode"),
        CheckConstraint(
            "guard IN ('ACTIVE','HOLD_PROMOTION','STOP_SERVING')",
            name="release_target_guard",
        ),
        CheckConstraint("epoch > 0", name="release_target_epoch_positive"),
        CheckConstraint("next_attempt_sequence >= 0", name="release_attempt_sequence_nonnegative"),
        CheckConstraint("published_revision >= 0", name="release_published_revision_nonnegative"),
    )


class ReleaseGrant(Base):
    __tablename__ = "release_grants"

    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    target_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    nonce_hash: Mapped[bytes] = mapped_column(LargeBinary(32), primary_key=True)
    subject_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    subject_body: Mapped[dict] = mapped_column(JSONB, nullable=False)
    approval_set_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    incarnation: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    org_epoch: Mapped[int] = mapped_column(BigInteger, nullable=False)
    target_epoch: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expected_prior_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    selection_sequence: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "target_id"], ["release_targets.org_id", "release_targets.id"]
        ),
        CheckConstraint("octet_length(nonce_hash) = 32", name="release_grant_nonce_length"),
        CheckConstraint("octet_length(subject_sha256) = 32", name="release_grant_subject_length"),
        CheckConstraint("octet_length(approval_set_sha256) = 32", name="release_grant_approval_length"),
        CheckConstraint(
            "status IN ('GRANTED','REDEEMED','CANCELED','EXPIRED')",
            name="release_grant_status",
        ),
    )


class ReleaseSelection(Base):
    """Never-recycled attempt sequence, not a published revision."""

    __tablename__ = "release_selections"

    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    target_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    attempt_sequence: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    grant_nonce_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    subject_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    staging_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    prior_published_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    witness_version_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    witness_sha256: Mapped[bytes | None] = mapped_column(LargeBinary(32), nullable=True)

    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "target_id", "grant_nonce_hash"],
            ["release_grants.org_id", "release_grants.target_id", "release_grants.nonce_hash"],
        ),
        UniqueConstraint(
            "org_id", "target_id", "grant_nonce_hash",
            name="uq_release_selection_grant",
        ),
        CheckConstraint("attempt_sequence > 0", name="release_attempt_positive"),
        CheckConstraint("octet_length(subject_sha256) = 32", name="release_selection_subject_length"),
        CheckConstraint("octet_length(staging_sha256) = 32", name="release_selection_staging_length"),
        CheckConstraint(
            "witness_sha256 IS NULL OR octet_length(witness_sha256) = 32",
            name="release_selection_witness_length",
        ),
        CheckConstraint(
            "state IN ('SELECTED_UNWITNESSED','WITNESSED','PUBLISHED','CANCELED','EXPIRED')",
            name="release_selection_state",
        ),
    )


class ReleasePublication(Base):
    __tablename__ = "release_publications"

    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    target_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    published_revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    attempt_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    witness_version_id: Mapped[str] = mapped_column(String(256), nullable=False)
    witness_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    representation_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    delivery_profile_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    fixed_bundle_sha256: Mapped[bytes | None] = mapped_column(LargeBinary(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    origin_bucket: Mapped[str | None] = mapped_column(String(63), nullable=True)
    origin_key: Mapped[str | None] = mapped_column(String(256), nullable=True)
    origin_version_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="PENDING_SEAL")
    receipt_version_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    receipt_sha256: Mapped[bytes | None] = mapped_column(LargeBinary(32), nullable=True)

    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "target_id", "attempt_sequence"],
            ["release_selections.org_id", "release_selections.target_id", "release_selections.attempt_sequence"],
        ),
        UniqueConstraint(
            "org_id", "target_id", "attempt_sequence",
            name="uq_publication_for_selection",
        ),
        CheckConstraint("published_revision > 0", name="release_revision_positive"),
        CheckConstraint("octet_length(witness_sha256) = 32", name="release_publication_witness_length"),
        CheckConstraint("octet_length(representation_sha256) = 32", name="release_publication_bytes_length"),
        CheckConstraint("octet_length(delivery_profile_sha256) = 32", name="release_publication_profile_length"),
        CheckConstraint(
            "fixed_bundle_sha256 IS NULL OR octet_length(fixed_bundle_sha256) = 32",
            name="release_publication_bundle_hash",
        ),
        CheckConstraint("status IN ('PENDING_SEAL','SEALED')", name="release_publication_status"),
        CheckConstraint(
            "receipt_sha256 IS NULL OR octet_length(receipt_sha256) = 32",
            name="release_publication_receipt_length",
        ),
    )


class ReleaseEndorsement(Base):
    """Consumed reviewer challenge and immutable signed endorsement evidence."""

    __tablename__ = "release_endorsements"

    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    challenge_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), primary_key=True)
    subject_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    target_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    person_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    custody_group: Mapped[str] = mapped_column(String(64), nullable=False)
    enrollment_generation: Mapped[int] = mapped_column(BigInteger, nullable=False)
    signed_body: Mapped[dict] = mapped_column(JSONB, nullable=False)
    signature: Mapped[bytes] = mapped_column(LargeBinary(64), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(["org_id", "target_id"], ["release_targets.org_id", "release_targets.id"]),
        UniqueConstraint("org_id", "subject_sha256", "person_id", name="uq_release_endorsement_person"),
        UniqueConstraint("org_id", "subject_sha256", "key_id", name="uq_release_endorsement_key"),
        CheckConstraint("octet_length(challenge_sha256) = 32", name="release_endorsement_nonce_length"),
        CheckConstraint("octet_length(subject_sha256) = 32", name="release_endorsement_subject_length"),
        CheckConstraint("octet_length(signature) = 64", name="release_endorsement_signature_length"),
    )


class ReleaseObservation(Base):
    """Signed independent readback evidence. Not an approval or release fact."""

    __tablename__ = "release_observations"

    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    target_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    incarnation: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    published_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    attempt_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    observer_key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    cohort: Mapped[str] = mapped_column(String(64), nullable=False)
    expected_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    observed_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    expected_profile_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    observed_profile_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    http_status: Mapped[int] = mapped_column(Integer, nullable=False)
    complete_bytes: Mapped[bool] = mapped_column(Boolean, nullable=False)
    disposition: Mapped[str] = mapped_column(String(24), nullable=False)
    signed_body: Mapped[dict] = mapped_column(JSONB, nullable=False)
    signature: Mapped[bytes] = mapped_column(LargeBinary(128), nullable=False)
    measured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "target_id", "published_revision"],
            [
                "release_publications.org_id", "release_publications.target_id",
                "release_publications.published_revision",
            ],
        ),
        CheckConstraint("published_revision > 0", name="observation_revision"),
        CheckConstraint("attempt_sequence > 0", name="observation_attempt"),
        CheckConstraint("http_status BETWEEN 100 AND 599", name="observation_http_status"),
        CheckConstraint(
            "disposition IN ('MATCH','CURRENT_MISMATCH','COVERAGE_GAP','HISTORICAL')",
            name="observation_disposition",
        ),
        CheckConstraint("octet_length(expected_sha256) = 32", name="observation_expected_hash"),
        CheckConstraint("octet_length(observed_sha256) = 32", name="observation_observed_hash"),
        CheckConstraint("octet_length(expected_profile_sha256) = 32", name="observation_expected_profile"),
        CheckConstraint("octet_length(observed_profile_sha256) = 32", name="observation_observed_profile"),
        CheckConstraint("octet_length(signature) BETWEEN 8 AND 128", name="observation_signature_size"),
    )


class IncidentContainmentReceipt(Base):
    """Proof reference retained by the independent incident custodian role."""

    __tablename__ = "incident_containment_receipts"

    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    case_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    veto_generation: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    target_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    incarnation: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    root_version_id: Mapped[str] = mapped_column(String(256), nullable=False)
    archive_version_id: Mapped[str] = mapped_column(String(256), nullable=False)
    archive_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    gateway_count: Mapped[int] = mapped_column(Integer, nullable=False)
    recorded_by: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "case_id"],
            ["investigation_cases.org_id", "investigation_cases.id"],
        ),
        ForeignKeyConstraint(
            ["org_id", "target_id"],
            ["release_targets.org_id", "release_targets.id"],
        ),
        ForeignKeyConstraint(
            ["org_id", "recorded_by"],
            ["identities.org_id", "identities.id"],
        ),
        CheckConstraint("veto_generation > 0", name="incident_veto_generation"),
        CheckConstraint("gateway_count BETWEEN 1 AND 256", name="incident_gateway_count"),
        CheckConstraint("octet_length(archive_sha256) = 32", name="incident_archive_digest"),
    )
