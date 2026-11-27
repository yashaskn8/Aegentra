import json
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from hypothesis import given, settings, strategies as st
from pydantic import ValidationError

from aegentra.case_contracts import CaseTimelineEvent, CaseTimelineKind, CaseTimelinePage
from aegentra.case_timeline import InvalidTimelineCursor, decode_timeline_cursor, encode_timeline_cursor


UTC_START = datetime(2026, 1, 1, tzinfo=timezone.utc)
bounded = settings(max_examples=40, derandomize=True)


@bounded
@given(st.uuids(), st.uuids(), st.one_of(st.none(), st.uuids()), st.binary(min_size=32, max_size=32),
       st.integers(min_value=0, max_value=86400000))
def test_timeline_cursor_round_trips_and_binds_all_scopes(
    org_id: UUID, case_id: UUID, evidence_id: UUID | None, digest: bytes, millis: int,
) -> None:
    when = UTC_START + timedelta(milliseconds=millis)
    cursor = encode_timeline_cursor(org_id, case_id, evidence_id, when, digest)
    assert decode_timeline_cursor(cursor, org_id, case_id, evidence_id) == (when, digest)
    for scope in (
        (UUID(int=org_id.int ^ 1), case_id, evidence_id),
        (org_id, UUID(int=case_id.int ^ 1), evidence_id),
        (org_id, case_id, UUID(int=0) if evidence_id is None else None),
    ):
        with pytest.raises(InvalidTimelineCursor):
            decode_timeline_cursor(cursor, *scope)
    with pytest.raises(InvalidTimelineCursor):
        decode_timeline_cursor(cursor + "=", org_id, case_id, evidence_id)


@bounded
@given(st.lists(st.tuples(st.integers(0, 3), st.binary(min_size=32, max_size=32)),
                min_size=2, max_size=30, unique=True), st.integers(1, 8))
def test_repeated_time_cursor_boundaries_preserve_keyset_order(
    offsets: list[tuple[int, bytes]], page_size: int,
) -> None:
    expected = sorted((UTC_START + timedelta(seconds=delay), key) for delay, key in offsets)
    org_id, case_id = UUID(int=1), UUID(int=2)
    remaining = expected
    collected = []
    while remaining:
        page = remaining[:page_size]
        cursor = encode_timeline_cursor(org_id, case_id, None, *page[-1])
        last = decode_timeline_cursor(cursor, org_id, case_id, None)
        remaining = [row for row in remaining if row > last]
        collected.extend(page)
    assert collected == expected


@bounded
@given(st.uuids(), st.integers(min_value=1, max_value=2147483647), st.sampled_from(list(CaseTimelineKind)))
def test_wire_model_preserves_evidence_ids_and_distinguishes_absent_details(
    evidence_id: UUID, revision: int, kind: CaseTimelineKind,
) -> None:
    ref = evidence_id if kind is CaseTimelineKind.CASE_EVIDENCE_LINKED else None
    version = revision if kind.startswith("INCIDENT_") else None
    item = CaseTimelineEvent(id="a" * 64, occurred_at=UTC_START, kind=kind, evidence_id=ref, revision=version)
    page = CaseTimelinePage(items=[item], next_cursor=None)
    raw = page.model_dump(mode="json")["items"][0]
    assert raw["evidence_id"] == (None if ref is None else str(ref))
    assert raw["revision"] == version
    assert CaseTimelinePage.model_validate_json(page.model_dump_json()) == page
    raw["evidence_id"] = None if ref is not None else str(evidence_id)
    with pytest.raises(ValidationError):
        CaseTimelineEvent.model_validate_json(json.dumps(raw))


@pytest.mark.parametrize("bad", [None, False, "1"])
def test_incident_requires_integer_revision(bad: object) -> None:
    with pytest.raises(ValidationError):
        CaseTimelineEvent.model_validate({
            "id": "a" * 64, "occurred_at": UTC_START, "kind": CaseTimelineKind.INCIDENT_TRIAGED,
            "evidence_id": None, "revision": bad,
        })
