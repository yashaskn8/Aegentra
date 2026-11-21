"""Fenced native EC2/EBS creation with durable before-call intents.

This library has no CLI or public route. Live mutation is disabled by default:
it requires explicit enablement by an independently qualified native operator.
No AWS actions are executed in repository tests or CI. It does not attach
volumes, run a guest workload, claim image provenance, or authorize release.
"""
from __future__ import annotations

import asyncio
import copy
import re
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegentra.bridge_journal import LaunchReservation
from aegentra.guest_creation import (
    KINDS, prepare_creation, quarantine_creation, record_creation,
)
from aegentra.native_ami_preflight import AmiCandidate
from aegentra.native_isolation_guard import IsolationCandidate
from aegentra.native_launch_preflight import LaunchPlan, _plan
from aegentra.persistence import organization_session


class CreationUnknown(RuntimeError):
    """Do not replay this operation. Reconcile the exact AWS intent manually."""

    def __init__(self, message: str, *, resource_id: str | None = None):
        super().__init__(message)
        self.resource_id = resource_id


def _parse_result(kind: str, result: Any, pinned: LaunchReservation) -> str:
    if not isinstance(result, dict):
        raise ValueError("AWS creation response is not an object")
    if kind in ("INPUT_EBS", "OUTPUT_EBS"):
        resource = result.get("VolumeId")
        if (
            not isinstance(resource, str)
            or re.fullmatch(r"vol-[0-9a-f]{8,17}", resource) is None
            or result.get("AvailabilityZone") != pinned.availability_zone
            or result.get("Encrypted") is not True
            or result.get("KmsKeyId") != pinned.kms_key_arn
            or result.get("VolumeType") != "gp3"
            or result.get("Size") != 1
            or result.get("State") not in ("creating", "available")
        ):
            raise ValueError("untrusted AWS EBS create response")
        return resource

    rows = result.get("Instances")
    if (
        kind != "INSTANCE" or not isinstance(rows, list) or len(rows) != 1
        or not isinstance(rows[0], dict)
    ):
        raise ValueError("untrusted AWS instance create response")
    instance = rows[0]
    resource = instance.get("InstanceId")
    if (
        not isinstance(resource, str)
        or re.fullmatch(r"i-[0-9a-f]{8,17}", resource) is None
        or instance.get("ImageId") != pinned.ami_id
        or not isinstance(instance.get("Placement"), dict)
        or instance["Placement"].get("AvailabilityZone") != pinned.availability_zone
        or not isinstance(instance.get("MetadataOptions"), dict)
        or instance["MetadataOptions"].get("HttpEndpoint") != "disabled"
        or instance.get("PublicIpAddress") is not None
        or instance.get("IamInstanceProfile") is not None
    ):
        raise ValueError("untrusted AWS instance identity or isolation response")
    return resource


def _checked_plan(plan: LaunchPlan, pinned: LaunchReservation, region: str) -> None:
    expected = _plan(
        pinned=pinned,
        image=AmiCandidate(pinned.ami_id, "snap-pinned"),
        network=IsolationCandidate(
            vpc_id="vpc-pinned", subnet_id=pinned.subnet_id,
            security_group_id=pinned.security_group_id,
        ),
        region=region,
    )
    if plan != expected or plan.status != "SHADOW_ONLY_EXTERNAL_QUALIFICATION_REQUIRED":
        raise ValueError("untrusted or changed AWS creation request plan")


async def create_guest_resources(
    *, sessions: async_sessionmaker[AsyncSession], ec2: Any,
    pinned: LaunchReservation, actor_id: UUID,
    plan: LaunchPlan, region: str,
    explicitly_enabled: bool = False,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> tuple[str, str, str]:
    """Create one input, one output EBS and one EC2 instance, each journaled.

    Invariant per operation: commit PREPARED -> one AWS request -> commit ID.
    A timeout or invalid/ambiguous response durably quarantines the attempt.
    After a successful AWS call but failed DB commit, caller must reconcile
    manually; never retry the same action without independently checking AWS.
    This function never attaches volumes or executes the guest.
    """
    if not explicitly_enabled:
        raise PermissionError("live AWS mutation requires separate operator enablement")
    _checked_plan(plan, pinned, region)
    if not isinstance(actor_id, UUID) or pinned.generation < 1:
        raise ValueError("native bridge actor or generation untrusted")

    requests = {
        "INPUT_EBS": ("create_volume", copy.deepcopy(plan.create_volumes[0])),
        "OUTPUT_EBS": ("create_volume", copy.deepcopy(plan.create_volumes[1])),
        "INSTANCE": ("run_instances", copy.deepcopy(plan.run_instances)),
    }
    digest = plan.sha256()
    saved: list[str] = []
    for kind in KINDS:
        method_name, request = requests[kind]
        token = request["ClientToken"]
        async with organization_session(sessions, pinned.org_id) as session:
            await prepare_creation(
                session, org_id=pinned.org_id, job_id=pinned.job_id,
                generation=pinned.generation, actor_id=actor_id, kind=kind,
                plan_sha256=digest, client_token=token, now=clock(),
            )
        try:
            method = getattr(ec2, method_name)
            result = await asyncio.to_thread(method, **request)
            resource_id = _parse_result(kind, result, pinned)
        except Exception as exc:
            try:
                async with organization_session(sessions, pinned.org_id) as session:
                    await quarantine_creation(
                        session, org_id=pinned.org_id, job_id=pinned.job_id,
                        generation=pinned.generation, actor_id=actor_id,
                        kind=kind, now=clock(),
                    )
            except Exception as journal_error:
                raise CreationUnknown(
                    "AWS creation outcome unknown AND quarantine could not be committed"
                ) from journal_error
            raise CreationUnknown("AWS creation outcome unknown; attempt quarantined") from exc

        try:
            async with organization_session(sessions, pinned.org_id) as session:
                status = await record_creation(
                    session, org_id=pinned.org_id, job_id=pinned.job_id,
                    generation=pinned.generation, actor_id=actor_id,
                    kind=kind, plan_sha256=digest, client_token=token,
                    resource_id=resource_id, now=clock(),
                )
        except Exception as exc:
            raise CreationUnknown(
                "AWS returned a physical ID but its durable journal result is unknown",
                resource_id=resource_id,
            ) from exc
        if status != "RECORDED":
            raise CreationUnknown(
                "AWS physical create completed after the trusted lease; quarantined",
                resource_id=resource_id,
            )
        saved.append(resource_id)
    return (saved[0], saved[1], saved[2])
