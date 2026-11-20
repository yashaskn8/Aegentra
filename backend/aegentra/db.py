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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(["org_id", "stream"], ["audit_streams.org_id", "audit_streams.stream"]),
        CheckConstraint("octet_length(previous_hash) = 32", name="audit_prev_length"),
        CheckConstraint("octet_length(event_hash) = 32", name="audit_event_length"),
        CheckConstraint("octet_length(body_hash) = 32", name="audit_body_length"),
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

    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "stream", "sequence"],
            ["audit_entries.org_id", "audit_entries.stream", "audit_entries.sequence"],
        ),
        UniqueConstraint("org_id", "stream", "sequence", name="uq_outbox_event"),
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
    status: Mapped[str] = mapped_column(String(12), nullable=False, default="OPEN")
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(["org_id", "asset_id"], ["assets.org_id", "assets.id"]),
        ForeignKeyConstraint(["org_id", "created_by"], ["identities.org_id", "identities.id"]),
        UniqueConstraint("org_id", "asset_id", "id", name="uq_case_org_asset_id"),
        CheckConstraint("status IN ('OPEN', 'CLOSED')", name="case_status"),
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
            "'DETACHED_VERIFIED','QUARANTINED','DISPOSED')",
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
