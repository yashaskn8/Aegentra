"""Trusted bridge-side structural validation of untrusted guest output.

Passing validation only produces advisory investigative leads. A guest cannot
prove its own EC2 custody, network isolation, trusted toolchain or release
eligibility. Those need independent authority and operational measurements.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from aegentra.guest_protocol import FrameError, GuestRequest, decode_output


@dataclass(frozen=True)
class ValidatedLead:
    result_sha256: str
    source_sha256: str
    status: str
    coverage: str
    finding_count: int
    reason: str | None
    disposition: str


def validate_guest_result(
    *,
    expected: GuestRequest,
    original_source: bytes,
    raw_result: bytes,
) -> ValidatedLead:
    """Recheck every scoped identity, original-byte span and coverage state."""
    if len(original_source) != expected.byte_length:
        raise FrameError("trusted input length mismatch")
    original_digest = hashlib.sha256(original_source).hexdigest()
    if not hmac.compare_digest(original_digest, expected.source_sha256):
        raise FrameError("trusted input digest mismatch")

    guest = decode_output(raw_result)
    if (
        guest.org_id != expected.org_id
        or guest.job_id != expected.job_id
        or guest.generation != expected.generation
        or not hmac.compare_digest(guest.nonce, expected.nonce)
        or not hmac.compare_digest(guest.toolchain_sha256, expected.toolchain_sha256)
        or not hmac.compare_digest(guest.source_sha256, original_digest)
        or guest.byte_length != expected.byte_length
    ):
        raise FrameError("guest result does not match fenced attempt")

    seen: set[tuple[str, int, int]] = set()
    for finding in guest.findings:
        if finding.end_byte_exclusive > len(original_source):
            raise FrameError("finding outside original bytes")
        span = (finding.rule_id, finding.start_byte, finding.end_byte_exclusive)
        if span in seen:
            raise FrameError("duplicate finding span")
        seen.add(span)
        if finding.symbol.encode("ascii") not in original_source[
            finding.start_byte:finding.end_byte_exclusive
        ]:
            raise FrameError("finding has no matching source symbol")

    # This is NOT independent detection verification or permission to publish.
    return ValidatedLead(
        result_sha256=hashlib.sha256(raw_result).hexdigest(),
        source_sha256=original_digest,
        status=guest.status,
        coverage=guest.coverage,
        finding_count=len(guest.findings),
        reason=guest.reason,
        disposition=(
            "ADVISORY_PENDING_INDEPENDENT_REVIEW" if guest.status == "COMPLETE"
            else "REQUIRED_ANALYSIS_INCOMPLETE"
        ),
    )
