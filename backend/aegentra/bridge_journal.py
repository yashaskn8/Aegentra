"""Bridge-only journal for a disposable offline EC2 scan attempt.

An ordinary web session cannot reserve or modify these records. Live EC2
operations must be performed by a separate management principal and all
physical resources recorded *before* attachment or guest use.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegentra.audit import record_event
from aegentra.bridge_custody import (
    AttemptCustody, verify_two_pass_cleanup,
)
from aegentra.db import GuestAttempt, GuestResource, ScanJob


class BridgeConflict(ValueError):
    pass


_VOLUME = re.compile(r"vol-[0-9a-f]{8,17}\Z")
_INSTANCE = re.compile(r"i-[0-9a-f]{8,17}\Z")


async def reserve_attempt(
    session: AsyncSession, *,
    org_id: UUID, job_id: UUID, actor_id: UUID, generation: int,
    nonce: str, input_sha256: bytes, toolchain_sha256: bytes,
    account_id: str, availability_zone: str, subnet_id: str,
    security_group_id: str, kms_key_arn: str, now: datetime,
) -> None:
    if now.tzinfo is None or any(len(digest) != 32 for digest in (input_sha256, toolchain_sha256)):
        raise BridgeConflict("invalid trusted digest or timestamp")
    if not re.fullmatch(r"[0-9]{12}", account_id):
        raise BridgeConflict("invalid pinned AWS account")
    job = await session.scalar(
        select(ScanJob).where(
            ScanJob.org_id == org_id, ScanJob.id == job_id
        ).with_for_update()
    )
    if (
        job is None or job.status != "LEASED"
        or job.attempt_generation != generation
        or job.lease_nonce is None
        or not hmac.compare_digest(job.lease_nonce, nonce)
        or job.lease_expires is None or now >= job.lease_expires
        or job.attempt_deadline is None or now >= job.attempt_deadline
    ):
        raise BridgeConflict("stale or unauthorized scan lease")
    if not all((availability_zone, subnet_id, security_group_id, kms_key_arn)):
        raise BridgeConflict("missing trusted AWS configuration")
    existing = await session.scalar(
        select(GuestAttempt).where(
            GuestAttempt.org_id == org_id, GuestAttempt.job_id == job_id,
            GuestAttempt.generation == generation,
        )
    )
    if existing is not None:
        raise BridgeConflict("physical attempt has already been reserved")
    session.add(GuestAttempt(
        org_id=org_id, job_id=job_id, generation=generation,
        nonce_sha256=hashlib.sha256(nonce.encode("ascii")).digest(),
        input_sha256=input_sha256, toolchain_sha256=toolchain_sha256,
        account_id=account_id, availability_zone=availability_zone,
        subnet_id=subnet_id, security_group_id=security_group_id,
        kms_key_arn=kms_key_arn, state="RESERVED",
        created_at=now, updated_at=now,
    ))
    await session.flush()
    await record_event(
        session, org_id=org_id, actor_id=actor_id, stream="scan",
        event_type="GUEST_ATTEMPT_RESERVED",
        body={"job_id": str(job_id), "generation": generation},
    )


async def record_volumes(
    session: AsyncSession, *, org_id: UUID, job_id: UUID, actor_id: UUID,
    generation: int, input_volume_id: str, output_volume_id: str,
    now: datetime,
) -> None:
    if (
        input_volume_id == output_volume_id
        or not _VOLUME.fullmatch(input_volume_id)
        or not _VOLUME.fullmatch(output_volume_id)
    ):
        raise BridgeConflict("invalid or overlapping EBS volume IDs")
    attempt = await _locked(session, org_id, job_id, generation)
    if attempt.state != "RESERVED":
        raise BridgeConflict("volumes already bound or attempt quarantined")
    for resource_id, kind in (
        (input_volume_id, "INPUT_EBS"), (output_volume_id, "OUTPUT_EBS")
    ):
        session.add(GuestResource(
            resource_id=resource_id, org_id=org_id, job_id=job_id,
            generation=generation, kind=kind,
        ))
    await session.flush()  # Global PK prohibits any volume reuse, across roles.
    attempt.state, attempt.updated_at = "VOLUMES_RECORDED", now
    await record_event(
        session, org_id=org_id, actor_id=actor_id, stream="scan",
        event_type="GUEST_VOLUMES_RECORDED",
        body={"job_id": str(job_id), "generation": generation},
    )


async def record_instance(
    session: AsyncSession, *, org_id: UUID, job_id: UUID, actor_id: UUID,
    generation: int, instance_id: str, now: datetime,
) -> None:
    if not _INSTANCE.fullmatch(instance_id):
        raise BridgeConflict("invalid EC2 instance ID")
    attempt = await _locked(session, org_id, job_id, generation)
    if attempt.state != "VOLUMES_RECORDED":
        raise BridgeConflict("instance cannot be bound before both volumes")
    session.add(GuestResource(
        resource_id=instance_id, org_id=org_id, job_id=job_id,
        generation=generation, kind="INSTANCE",
    ))
    await session.flush()
    attempt.state, attempt.updated_at = "INSTANCE_RECORDED", now
    await record_event(
        session, org_id=org_id, actor_id=actor_id, stream="scan",
        event_type="GUEST_INSTANCE_RECORDED",
        body={"job_id": str(job_id), "generation": generation},
    )


async def record_verified_detach(
    session: AsyncSession, *, org_id: UUID, job_id: UUID, actor_id: UUID,
    generation: int, now: datetime,
    first_instances: list[dict], first_volumes: list[dict],
    second_instances: list[dict], second_volumes: list[dict],
) -> AttemptCustody:
    attempt = await _locked(session, org_id, job_id, generation)
    if attempt.state != "INSTANCE_RECORDED":
        raise BridgeConflict("physical attempt not ready for detach verification")
    resources = (await session.scalars(
        select(GuestResource).where(
            GuestResource.org_id == org_id, GuestResource.job_id == job_id,
            GuestResource.generation == generation,
        )
    )).all()
    names = {r.kind: r.resource_id for r in resources}
    if set(names) != {"INPUT_EBS", "OUTPUT_EBS", "INSTANCE"}:
        raise BridgeConflict("incomplete physical inventory")
    expected = AttemptCustody(
        job_id=job_id, generation=generation, account_id=attempt.account_id,
        availability_zone=attempt.availability_zone,
        instance_id=names["INSTANCE"], subnet_id=attempt.subnet_id,
        security_group_id=attempt.security_group_id,
        input_volume_id=names["INPUT_EBS"],
        output_volume_id=names["OUTPUT_EBS"],
        kms_key_arn=attempt.kms_key_arn,
    )
    verify_two_pass_cleanup(
        expected=expected, account_id=attempt.account_id,
        first_instances=first_instances, first_volumes=first_volumes,
        second_instances=second_instances, second_volumes=second_volumes,
    )
    attempt.state, attempt.updated_at = "DETACHED_VERIFIED", now
    await record_event(
        session, org_id=org_id, actor_id=actor_id, stream="scan",
        event_type="GUEST_DETACH_RECORDED",
        body={"job_id": str(job_id), "generation": generation},
    )
    return expected


async def quarantine_attempt(
    session: AsyncSession, *, org_id: UUID, job_id: UUID, actor_id: UUID,
    generation: int, now: datetime,
) -> None:
    attempt = await _locked(session, org_id, job_id, generation)
    if attempt.state in {"DISPOSED", "QUARANTINED"}:
        return
    attempt.state, attempt.updated_at = "QUARANTINED", now
    await record_event(
        session, org_id=org_id, actor_id=actor_id, stream="scan",
        event_type="GUEST_QUARANTINED",
        body={"job_id": str(job_id), "generation": generation},
    )


async def _locked(session: AsyncSession, org: UUID, job: UUID, generation: int) -> GuestAttempt:
    attempt = await session.scalar(
        select(GuestAttempt).where(
            GuestAttempt.org_id == org,
            GuestAttempt.job_id == job, GuestAttempt.generation == generation,
        ).with_for_update()
    )
    if attempt is None:
        raise BridgeConflict("physical attempt unavailable")
    return attempt
