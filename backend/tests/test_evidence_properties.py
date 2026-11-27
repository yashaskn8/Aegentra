import hashlib
import json
from collections.abc import Iterable, Iterator

import pytest
from hypothesis import given, settings, strategies as st
from pydantic import ValidationError

from aegentra.bounded_json import ManifestError, strict_json
from aegentra.content_manifest import parse_manifest_json
from aegentra.coverage import CoverageCheck, CoverageState, assess_coverage
from aegentra.evidence_verifier import EvidenceMismatch, VerifiedBlob, verify_versioned_blob


bounded = settings(max_examples=32, derandomize=True)


@bounded
@given(st.dictionaries(st.text(max_size=12), st.text(max_size=32), max_size=8))
def test_utf8_json_round_trips_with_an_exact_byte_limit(value: dict[str, str]) -> None:
    data = json.dumps(value, ensure_ascii=False).encode("utf-8")
    assert strict_json(data, max_bytes=len(data)) == value
    with pytest.raises(ManifestError, match="size limit"):
        strict_json(data, max_bytes=len(data) - 1)


@bounded
@given(st.lists(st.integers(min_value=0, max_value=999), min_size=2, max_size=12, unique=True))
def test_manifest_identity_is_independent_of_list_order_and_rejects_repeated_paths(ids: list[int]) -> None:
    paths = [f"part-{number}.txt" for number in ids]
    parts = [
        {"path": path, "byte_length": 1, "sha256": "a" * 64, "media_type": "text/plain"}
        for path in paths
    ]
    edges = [{"source": source, "target": target} for source, target in zip(paths, paths[1:])]
    raw = {"schema_id": "aegentra.content.v1", "parts": parts, "edges": edges}
    first = parse_manifest_json(json.dumps(raw).encode())
    reversed_order = parse_manifest_json(json.dumps({
        **raw, "parts": list(reversed(parts)), "edges": list(reversed(edges)),
    }).encode())
    assert first.canonical_bytes() == reversed_order.canonical_bytes()
    assert first.sha256() == hashlib.sha256(first.canonical_bytes()).hexdigest()
    with pytest.raises(ValidationError, match="ambiguous content paths"):
        parse_manifest_json(json.dumps({**raw, "parts": [*parts, parts[0]]}).encode())


@bounded
@given(st.lists(st.binary(min_size=1, max_size=32), min_size=1, max_size=8))
def test_versioned_evidence_accounting_and_reader_lifecycle(chunks: list[bytes]) -> None:
    class Reader:
        closed = False

        def chunks(self, version_id: str) -> Iterable[bytes]:
            assert version_id == "synthetic-version"
            try:
                yield from chunks
            finally:
                self.closed = True

    reader = Reader()
    data = b"".join(chunks)
    expected = VerifiedBlob("synthetic-version", hashlib.sha256(data).hexdigest(), len(data))
    assert verify_versioned_blob(
        reader=reader,
        version_id=expected.version_id,
        expected_sha256=expected.sha256,
        expected_length=expected.byte_length,
    ) == expected
    assert reader.closed


@bounded
@given(st.binary(min_size=1, max_size=128))
def test_oversized_evidence_closes_a_retained_iterator_without_reading_its_tail(data: bytes) -> None:
    closed = False

    def stream() -> Iterator[bytes]:
        nonlocal closed
        try:
            yield data
            yield b"extra"
            pytest.fail("the reader advanced after crossing the declared size")
        finally:
            closed = True

    retained = stream()

    class Reader:
        def chunks(self, version_id: str) -> Iterable[bytes]:
            return retained

    with pytest.raises(EvidenceMismatch, match="oversized"):
        verify_versioned_blob(
            reader=Reader(),
            version_id="synthetic-version",
            expected_sha256=hashlib.sha256(data).hexdigest(),
            expected_length=len(data),
        )
    assert closed


@bounded
@given(st.lists(st.sampled_from([CoverageState.FAILED, CoverageState.UNKNOWN, CoverageState.UNSUPPORTED]),
                min_size=1, max_size=12))
def test_required_coverage_becomes_reviewable_only_after_every_gap_is_verified(states: list[CoverageState]) -> None:
    failed = tuple(CoverageCheck(name=f"check-{i}", required=True, state=state) for i, state in enumerate(states))
    verified = tuple(CoverageCheck(name=check.name, required=True, state=CoverageState.VERIFIED) for check in failed)
    for resolved in range(len(failed)):
        assessment = assess_coverage(verified[:resolved] + failed[resolved:])
        assert assessment.status == "INCOMPLETE"
        assert assessment.gaps == tuple(check.name for check in failed[resolved:])
    assert assess_coverage(verified).status == "REVIEWABLE"
