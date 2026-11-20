"""Audit reconciliation refuses missing entries, forks and mismatched tenant."""
import hashlib
from uuid import uuid4

import pytest

from aegentra.audit_reconcile import (
    AuditGap, VerifiedAuditHead, reconcile_audit_window,
)
from aegentra.db import AuditEntry


def fixture():
    org, actor = uuid4(), uuid4()
    prev = b"\x00" * 32
    events = []
    for seq in range(1, 4):
        content = hashlib.sha256(f"event-{seq}".encode()).digest()
        digest = hashlib.sha256(
            b"aegentra.audit.v1\x00" + org.bytes + b"release\x00"
            + seq.to_bytes(8, "big") + prev + content
        ).digest()
        events.append(AuditEntry(
            org_id=org, stream="release", sequence=seq,
            actor_id=actor, event_type="SIGNED_EVENT",
            previous_hash=prev, event_hash=digest, body_hash=content,
        ))
        prev = digest
    return org, events


def test_full_and_incremental_chain_match_without_missing_sequence():
    org, events = fixture()
    head = reconcile_audit_window(
        org_id=org, stream="release",
        previous=None, ordered=events,
        expected_head=events[-1].event_hash,
    )
    assert head.sequence == 3 and head.sha256 == events[-1].event_hash
    first = reconcile_audit_window(
        org_id=org, stream="release",
        previous=None, ordered=events[:1],
    )
    second = reconcile_audit_window(
        org_id=org, stream="release",
        previous=first, ordered=events[1:],
        expected_head=head.sha256,
    )
    assert second == head


@pytest.mark.parametrize("tamper", [
    "gap", "duplicate", "wrong_org", "wrong_stream",
    "wrong_previous", "changed_content", "changed_head",
])
def test_every_audit_gap_fork_and_tamper_is_rejected(tamper):
    org, events = fixture()
    selected = list(events)
    expected_head = events[-1].event_hash
    if tamper == "gap":
        selected.pop(1)
    elif tamper == "duplicate":
        selected[1] = selected[0]
    elif tamper == "wrong_org":
        selected[0].org_id = uuid4()
    elif tamper == "wrong_stream":
        selected[1].stream = "cases"
    elif tamper == "wrong_previous":
        selected[1].previous_hash = b"z" * 32
    elif tamper == "changed_content":
        selected[0].body_hash = b"x" * 32
    else:
        expected_head = b"q" * 32
    with pytest.raises(AuditGap):
        reconcile_audit_window(
            org_id=org, stream="release",
            previous=None, ordered=selected,
            expected_head=expected_head,
        )


def test_wrong_prior_checkpoint_or_oversized_window_rejected():
    org, events = fixture()
    wrong = VerifiedAuditHead(
        org_id=uuid4(), stream="release",
        sequence=1, sha256=events[0].event_hash,
    )
    with pytest.raises(AuditGap):
        reconcile_audit_window(
            org_id=org, stream="release",
            previous=wrong, ordered=events[1:],
        )
    with pytest.raises(AuditGap):
        reconcile_audit_window(
            org_id=org, stream="release",
            previous=None, ordered=events * 334,
        )


@pytest.mark.parametrize("terminal", [2, 4, 0, -1, True, "3"])
def test_expected_terminal_sequence_must_match_verified_window(terminal):
    org, events = fixture()
    with pytest.raises(AuditGap, match="terminal sequence"):
        reconcile_audit_window(
            org_id=org, stream="release", previous=None,
            ordered=events, expected_sequence=terminal,
        )


def test_truncated_tail_rejected_even_when_all_present_entries_are_valid():
    org, events = fixture()
    with pytest.raises(AuditGap, match="terminal sequence"):
        reconcile_audit_window(
            org_id=org, stream="release", previous=None,
            ordered=events[:2], expected_sequence=3,
        )
    head = reconcile_audit_window(
        org_id=org, stream="release", previous=None,
        ordered=events, expected_sequence=3,
        expected_head=events[-1].event_hash,
    )
    assert head.sequence == 3


@pytest.mark.parametrize("head", [b"short", "f" * 32, 123])
def test_malformed_advertised_head_fails_closed(head):
    org, events = fixture()
    with pytest.raises(AuditGap):
        reconcile_audit_window(
            org_id=org, stream="release", previous=None,
            ordered=events, expected_head=head,
        )
