"""Single inert guest analysis operation (native Linux guest process only).

The actual guest must boot with no IAM profile, network, IMDS or accessible
credentials. An independent bridge controls VM deadlines and block devices.
This module never imports, runs, installs or fetches submitted JavaScript.
"""
from __future__ import annotations

from aegentra.guest_protocol import (
    GuestFinding, GuestResponse, decode_input, encode_output,
)
from aegentra.static_analysis import inspect_inert_javascript


def analyze_frame(raw_input: bytes) -> bytes:
    request, source = decode_input(raw_input)
    report = inspect_inert_javascript(source)
    result = GuestResponse(
        kind="aegentra.guest.result.v1",
        org_id=request.org_id,
        job_id=request.job_id,
        generation=request.generation,
        nonce=request.nonce,
        toolchain_sha256=request.toolchain_sha256,
        source_sha256=report.content_sha256,
        byte_length=len(source),
        status=report.status,
        coverage=report.coverage,
        node_count=report.node_count,
        reason=report.reason,
        findings=tuple(
            GuestFinding(
                rule_id=item.rule_id,
                symbol=item.symbol,
                start_byte=item.start_byte,
                end_byte_exclusive=item.end_byte_exclusive,
                interpretation=item.interpretation,
            )
            for item in report.findings
        ),
    )
    return encode_output(result)
