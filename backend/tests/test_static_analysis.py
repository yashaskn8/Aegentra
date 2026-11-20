import hashlib

import pytest

from aegentra.static_analysis import (
    MAX_JS_BYTES, inspect_inert_javascript, report_for_release,
)


def test_small_inert_program_has_explicit_non_authorizing_result() -> None:
    raw = b"const answer = 42;\n"
    report = inspect_inert_javascript(raw)
    assert report.status == "COMPLETE"
    assert report.coverage == "VERIFIED"
    assert report.content_sha256 == hashlib.sha256(raw).hexdigest()
    assert report.findings == ()
    assert report_for_release(report) == "REQUIRES_INDEPENDENT_REVIEW"


def test_comment_and_string_do_not_masquerade_as_executable_calls() -> None:
    raw = b'// eval("hello")\nconst example = "fetch(123)";\n'
    report = inspect_inert_javascript(raw)
    assert report.status == "COMPLETE"
    assert report.findings == ()


def test_direct_call_is_lead_not_claim_about_global_runtime_binding() -> None:
    raw = b'const fetch = (v) => v; fetch(1);'
    report = inspect_inert_javascript(raw)
    assert len(report.findings) == 1
    assert report.findings[0].symbol == "fetch"
    assert report.findings[0].interpretation == "UNRESOLVED_BINDING"
    assert raw[report.findings[0].start_byte:report.findings[0].end_byte_exclusive] == b"fetch(1)"
    assert report_for_release(report) == "REQUIRES_INDEPENDENT_REVIEW"


def test_member_method_is_not_conflated_with_direct_call() -> None:
    report = inspect_inert_javascript(b'object.fetch("a");')
    assert report.status == "COMPLETE"
    assert report.findings == ()


@pytest.mark.parametrize("source,reason", [
    (b'function (', "SYNTAX_ERROR_OR_RECOVERY"),
    (b'var x = "\x00";', "NUL_BYTE"),
    (b'a' * (MAX_JS_BYTES + 1), "BYTE_LIMIT_EXCEEDED"),
])
def test_invalid_inputs_have_explicit_coverage_gap(source: bytes, reason: str) -> None:
    report = inspect_inert_javascript(source)
    assert report.status == "INCOMPLETE"
    assert report.reason == reason
    assert report_for_release(report) == "REQUIRED_ANALYSIS_INCOMPLETE"


def test_traversal_budget_fails_closed() -> None:
    raw = b"var a = 1;" * 1100
    report = inspect_inert_javascript(raw)
    assert report.status == "INCOMPLETE"
    assert report.reason == "NODE_LIMIT_EXCEEDED"


def test_original_bytes_only() -> None:
    with pytest.raises(TypeError):
        inspect_inert_javascript("const a = 1")  # type: ignore[arg-type]
