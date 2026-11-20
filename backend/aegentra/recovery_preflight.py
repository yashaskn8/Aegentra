"""SA-1.1 recovery reconciliation: conservative blocker report only.

A database PITR or AMI rollback is never enough to re-open protected traffic.
This assessor does not issue identities, clear external STOP, deploy or publish.
Its inputs must come from separately verified custodian evidence, not the UI.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from uuid import UUID


class RecoveryStatus(str, Enum):
    BLOCKED = "BLOCKED"
    READY_FOR_INDEPENDENT_REVIEW = "READY_FOR_INDEPENDENT_REVIEW"


@dataclass(frozen=True)
class RecoveryFacts:
    org_id: UUID
    old_incarnation: UUID
    restored_incarnation: UUID
    proposed_incarnation: UUID
    old_external_generation: int
    external_minimum_generation: int
    proposed_external_generation: int
    separate_custodians: int
    security_veto_still_active: bool
    old_writer_fenced: bool
    old_origin_exclusive_route_closed: bool
    restore_network_isolated: bool
    restored_all_credentials_quarantined: bool
    restored_egress_and_ai_disabled: bool
    all_immutable_witness_versions_reconciled: bool
    audit_streams_and_outbox_reconciled: bool
    unknown_selection_attempts_reconciled: bool
    published_and_observed_revisions_reconciled: bool
    deletion_tombstones_reconciled: bool
    consent_revocations_reconciled: bool
    prior_sessions_grants_and_approvals_invalidated: bool
    new_human_review_required: bool
    independent_origin_reenrollment_required: bool


@dataclass(frozen=True)
class RecoveryAssessment:
    status: RecoveryStatus
    blockers: tuple[str, ...]
    may_clear_veto: bool = False
    may_serve_protected_bytes: bool = False


def assess_recovery(facts: RecoveryFacts) -> RecoveryAssessment:
    """Inventory blockers without silently inferring a successful recovery."""
    blocked: list[str] = []

    def need(condition: bool, code: str) -> None:
        if not condition:
            blocked.append(code)

    need(
        facts.proposed_incarnation not in {
            facts.old_incarnation, facts.restored_incarnation
        }, "PROPOSED_INCARNATION_REUSED",
    )
    need(
        facts.old_external_generation > 0
        and facts.external_minimum_generation >= facts.old_external_generation
        and facts.proposed_external_generation > facts.external_minimum_generation,
        "EXTERNAL_MONOTONIC_FLOOR_UNPROVEN",
    )
    need(facts.separate_custodians >= 2, "DUAL_RECOVERY_CUSTODY_MISSING")
    checks = (
        ("SECURITY_VETO_NOT_ACTIVE", facts.security_veto_still_active),
        ("OLD_WRITER_NOT_FENCED", facts.old_writer_fenced),
        ("OLD_ORIGIN_ROUTE_NOT_CLOSED", facts.old_origin_exclusive_route_closed),
        ("RESTORE_NETWORK_NOT_ISOLATED", facts.restore_network_isolated),
        ("OLD_CREDENTIALS_NOT_QUARANTINED", facts.restored_all_credentials_quarantined),
        ("RESTORE_EGRESS_OR_AI_ENABLED", facts.restored_egress_and_ai_disabled),
        ("WITNESS_HISTORY_GAP", facts.all_immutable_witness_versions_reconciled),
        ("AUDIT_OR_OUTBOX_GAP", facts.audit_streams_and_outbox_reconciled),
        ("UNKNOWN_ATTEMPT_GAP", facts.unknown_selection_attempts_reconciled),
        ("PUBLICATION_READBACK_GAP", facts.published_and_observed_revisions_reconciled),
        ("DELETION_TOMBSTONE_GAP", facts.deletion_tombstones_reconciled),
        ("CONSENT_REVOCATION_GAP", facts.consent_revocations_reconciled),
        ("OLD_AUTHORIZATIONS_NOT_REVOKED", facts.prior_sessions_grants_and_approvals_invalidated),
        ("FRESH_HUMAN_REVIEW_MISSING", facts.new_human_review_required),
        ("INDEPENDENT_ORIGIN_REENROLLMENT_MISSING",
         facts.independent_origin_reenrollment_required),
    )
    for code, condition in checks:
        need(condition, code)
    # The top status is NOT an authority to resume or remove external STOP.
    return RecoveryAssessment(
        status=(
            RecoveryStatus.BLOCKED if blocked else
            RecoveryStatus.READY_FOR_INDEPENDENT_REVIEW
        ),
        blockers=tuple(blocked),
    )
