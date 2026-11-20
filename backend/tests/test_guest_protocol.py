"""Inert end-to-end fixtures: bounds, frame tampering and stale identities."""
import hashlib
import json
import struct
from uuid import uuid4

import pytest
import rfc8785

from aegentra.guest_protocol import (
    FrameError, GuestRequest, GuestResponse,
    decode_input, decode_output, encode_input, encode_output,
)
from aegentra.offline_guest import analyze_frame
from aegentra.trusted_result import validate_guest_result


DATA = b"// fetch(1)\nconst fetch = x => x; fetch(1);"


def request(source: bytes = DATA) -> GuestRequest:
    return GuestRequest(
        kind="aegentra.guest.input.v1", org_id=uuid4(), job_id=uuid4(),
        generation=1, nonce="x" * 43, toolchain_sha256="a" * 64,
        source_sha256=hashlib.sha256(source).hexdigest(),
        byte_length=len(source),
    )


def test_complete_guest_round_trip_stays_advisory() -> None:
    req = request()
    framed = encode_input(req, DATA)
    assert decode_input(framed) == (req, DATA)
    output = analyze_frame(framed)
    report = decode_output(output)
    assert report.coverage == "VERIFIED"
    assert len(report.findings) == 1
    assert report.findings[0].symbol == "fetch"
    lead = validate_guest_result(
        expected=req, original_source=DATA, raw_result=output,
    )
    assert lead.disposition == "ADVISORY_PENDING_INDEPENDENT_REVIEW"
    assert lead.finding_count == 1


def test_parse_failure_is_coverage_gap_not_clean_approval() -> None:
    src = b"function ("
    req = request(src)
    lead = validate_guest_result(
        expected=req, original_source=src,
        raw_result=analyze_frame(encode_input(req, src)),
    )
    assert lead.disposition == "REQUIRED_ANALYSIS_INCOMPLETE"
    assert lead.reason == "SYNTAX_ERROR_OR_RECOVERY"


@pytest.mark.parametrize("change", ["nonce", "generation", "org", "toolchain", "source"])
def test_fenced_identity_rejects_guest_result(change: str) -> None:
    req = request()
    report = decode_output(analyze_frame(encode_input(req, DATA)))
    replacements = {
        "nonce": {"nonce": "y" * 43},
        "generation": {"generation": 2},
        "org": {"org_id": uuid4()},
        "toolchain": {"toolchain_sha256": "b" * 64},
        "source": {"source_sha256": "b" * 64},
    }
    altered = report.model_copy(update=replacements[change])
    with pytest.raises(FrameError, match="fenced attempt"):
        validate_guest_result(
            expected=req, original_source=DATA,
            raw_result=encode_output(altered),
        )


def test_finding_out_of_bounds_and_duplicate_are_rejected() -> None:
    req = request()
    output = decode_output(analyze_frame(encode_input(req, DATA)))
    old = output.findings[0]
    far = old.model_copy(update={"end_byte_exclusive": len(DATA) + 1})
    for findings in ((far,), (old, old)):
        forged = output.model_copy(update={"findings": findings})
        with pytest.raises(FrameError):
            validate_guest_result(
                expected=req, original_source=DATA,
                raw_result=encode_output(forged),
            )


def test_input_digest_and_extra_bytes_rejected() -> None:
    req = request()
    frame = encode_input(req, DATA)
    with pytest.raises(FrameError):
        decode_input(frame + b"x")
    with pytest.raises(FrameError):
        decode_input(frame[:-1] + b"x")
    with pytest.raises(FrameError):
        encode_input(req, DATA + b"x")


def test_frame_rejects_noncanonical_duplicate_json_and_wrong_magic() -> None:
    req = request()
    valid = encode_input(req, DATA)
    with pytest.raises(FrameError):
        decode_input(b"WRNG" + valid[4:])
    n = struct.unpack(">I", valid[4:8])[0]
    data = json.loads(valid[8:8+n])
    blob = json.dumps(data).encode()
    with pytest.raises(FrameError):
        decode_input(b"AEGI" + struct.pack(">I", len(blob)) + blob + DATA)
    duplicate = valid[8:8+n][:-1] + b',"generation":1}'
    with pytest.raises(FrameError):
        decode_input(b"AEGI" + struct.pack(">I", len(duplicate)) + duplicate + DATA)


def test_invalid_guest_result_status_fails_closed() -> None:
    req = request()
    original = decode_output(analyze_frame(encode_input(req, DATA)))
    body = original.model_dump(mode="json")
    body["status"] = "INCOMPLETE"
    body["coverage"] = "VERIFIED"
    invalid = rfc8785.dumps(body)
    with pytest.raises(FrameError):
        decode_output(b"AEGO" + struct.pack(">I", len(invalid)) + invalid)
