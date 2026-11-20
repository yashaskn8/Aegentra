"""Validator-only ingestion of detached-guest advisory scan results.

This checks DB-fenced attempt identity and exact original bytes before
recording a single immutable receipt. It does not mark code safe, allow
deployment, sign attestation, or infer independent cloud isolation.
"""
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegentra.audit import record_event
from aegentra.db import GuestAttempt, ScanJob, ScanReceipt
from aegentra.guest_protocol import FrameError, GuestRequest
from aegentra.trusted_result import ValidatedLead, validate_guest_result


class ReceiptConflict(ValueError):
    pass


async def record_validated_receipt(
    session: AsyncSession, *,
    expected: GuestRequest,
    original_source: bytes,
    raw_result: bytes,
    actor_id: UUID,
    now: datetime,
) -> ValidatedLead:
    if now.tzinfo is None:
        raise ReceiptConflict("trusted validator clock must be timezone-aware")
    lead = validate_guest_result(
        expected=expected, original_source=original_source, raw_result=raw_result,
    )
    result_digest = bytes.fromhex(lead.result_sha256)
    job = await session.scalar(
        select(ScanJob).where(
            ScanJob.org_id == expected.org_id, ScanJob.id == expected.job_id,
        ).with_for_update()
    )
    attempt = await session.scalar(
        select(GuestAttempt).where(
            GuestAttempt.org_id == expected.org_id,
            GuestAttempt.job_id == expected.job_id,
            GuestAttempt.generation == expected.generation,
        )
    )
    if (
        job is None or job.status != "PENDING_TRUSTED_VALIDATION"
        or job.attempt_generation != expected.generation
        or job.result_sha256 is None
        or not hmac.compare_digest(job.result_sha256, result_digest)
        or attempt is None or attempt.state != "DETACHED_VERIFIED"
        or not hmac.compare_digest(
            attempt.nonce_sha256,
            hashlib.sha256(expected.nonce.encode("ascii")).digest(),
        )
        or not hmac.compare_digest(
            attempt.input_sha256, bytes.fromhex(expected.source_sha256),
        )
        or not hmac.compare_digest(
            attempt.toolchain_sha256, bytes.fromhex(expected.toolchain_sha256),
        )
    ):
        raise ReceiptConflict("untrusted, stale or incomplete physical attempt")

    existing = await session.scalar(
        select(ScanReceipt).where(
            ScanReceipt.org_id == expected.org_id,
            ScanReceipt.job_id == expected.job_id,
            ScanReceipt.generation == expected.generation,
        )
    )
    if existing is not None:
        if (
            existing.result_sha256 != result_digest
            or existing.source_sha256.hex() != lead.source_sha256
            or existing.coverage != lead.coverage
            or existing.status != lead.status
        ):
            raise ReceiptConflict("attempt receipt fork")
        return lead

    session.add(ScanReceipt(
        org_id=expected.org_id, job_id=expected.job_id,
        generation=expected.generation, result_sha256=result_digest,
        source_sha256=bytes.fromhex(lead.source_sha256),
        toolchain_sha256=bytes.fromhex(expected.toolchain_sha256),
        status=lead.status, coverage=lead.coverage,
        finding_count=lead.finding_count, reason=lead.reason, created_at=now,
    ))
    await session.flush()
    await record_event(
        session, org_id=expected.org_id, actor_id=actor_id, stream="scan",
        event_type="SCAN_ADVISORY_RECEIPT_RECORDED",
        body={
            "job_id": str(expected.job_id),
            "generation": expected.generation,
            "result_sha256": lead.result_sha256,
            "coverage": lead.coverage,
        },
    )
    return lead
