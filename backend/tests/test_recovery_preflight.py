"""Recovery assesses gaps but never clears STOP or certifies restored state."""
from dataclasses import replace
from uuid import uuid4

import pytest

from aegentra.recovery_preflight import (
    RecoveryFacts, RecoveryStatus, assess_recovery,
)


def fixture() -> RecoveryFacts:
    old = uuid4()
    return RecoveryFacts(
        org_id=uuid4(), old_incarnation=old,
        restored_incarnation=old, proposed_incarnation=uuid4(),
        old_external_generation=5, external_minimum_generation=5,
        proposed_external_generation=6, separate_custodians=2,
        security_veto_still_active=True, old_writer_fenced=True,
        old_origin_exclusive_route_closed=True,
        restore_network_isolated=True,
        restored_all_credentials_quarantined=True,
        restored_egress_and_ai_disabled=True,
        all_immutable_witness_versions_reconciled=True,
        audit_streams_and_outbox_reconciled=True,
        unknown_selection_attempts_reconciled=True,
        published_and_observed_revisions_reconciled=True,
        deletion_tombstones_reconciled=True,
        consent_revocations_reconciled=True,
        prior_sessions_grants_and_approvals_invalidated=True,
        new_human_review_required=True,
        independent_origin_reenrollment_required=True,
    )


def test_complete_inventory_still_does_not_authorize_serving_or_veto_clear():
    result = assess_recovery(fixture())
    assert result.status == RecoveryStatus.READY_FOR_INDEPENDENT_REVIEW
    assert result.blockers == ()
    assert not result.may_clear_veto
    assert not result.may_serve_protected_bytes


@pytest.mark.parametrize("name", [
    "security_veto_still_active",
    "old_writer_fenced",
    "old_origin_exclusive_route_closed",
    "restore_network_isolated",
    "restored_all_credentials_quarantined",
    "restored_egress_and_ai_disabled",
    "all_immutable_witness_versions_reconciled",
    "audit_streams_and_outbox_reconciled",
    "unknown_selection_attempts_reconciled",
    "published_and_observed_revisions_reconciled",
    "deletion_tombstones_reconciled",
    "consent_revocations_reconciled",
    "prior_sessions_grants_and_approvals_invalidated",
    "new_human_review_required",
    "independent_origin_reenrollment_required",
])
def test_every_missing_p0_recovery_fact_blocks(name):
    facts = replace(fixture(), **{name: False})
    result = assess_recovery(facts)
    assert result.status == RecoveryStatus.BLOCKED
    assert result.blockers
    assert not result.may_clear_veto
    assert not result.may_serve_protected_bytes


def test_previously_used_incarnation_or_rolled_back_floor_blocks():
    facts = fixture()
    for bad in (
        replace(facts, proposed_incarnation=facts.old_incarnation),
        replace(facts, proposed_incarnation=facts.restored_incarnation),
        replace(facts, external_minimum_generation=4),
        replace(facts, proposed_external_generation=5),
        replace(facts, separate_custodians=1),
    ):
        result = assess_recovery(bad)
        assert result.status == RecoveryStatus.BLOCKED
        assert not result.may_clear_veto


def test_all_blockers_reported_for_operator_reconciliation():
    facts = replace(
        fixture(), security_veto_still_active=False,
        old_writer_fenced=False, deletion_tombstones_reconciled=False,
    )
    result = assess_recovery(facts)
    assert set(result.blockers) >= {
        "SECURITY_VETO_NOT_ACTIVE", "OLD_WRITER_NOT_FENCED",
        "DELETION_TOMBSTONE_GAP",
    }
