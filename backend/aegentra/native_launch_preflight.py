"""One-shot, read-only native EC2 launch preflight and constrained request plan.

This module never calls CreateVolume, RunInstances, AttachVolume or any other
AWS mutation. Qualified AMI provenance, separate hardware custodians, native
network drills and an independently approved lifecycle supervisor are still
required before an external operator can launch a disposable guest.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import rfc8785
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegentra.bridge_journal import LaunchReservation, load_reserved_launch
from aegentra.native_ami_preflight import AmiCandidate, AmiPin, verify_native_ami
from aegentra.native_isolation_collector import evaluate_native_guest_network
from aegentra.native_isolation_guard import GuestNetworkPin, IsolationCandidate
from aegentra.persistence import make_engine, organization_session


class LaunchPreflightRejected(ValueError):
    pass


@dataclass(frozen=True)
class LaunchPlan:
    run_instances: dict[str, Any]
    create_volumes: tuple[dict[str, Any], dict[str, Any]]
    status: str = "SHADOW_ONLY_EXTERNAL_QUALIFICATION_REQUIRED"

    def sha256(self) -> str:
        return hashlib.sha256(rfc8785.dumps({
            "run_instances": self.run_instances,
            "create_volumes": list(self.create_volumes),
        })).hexdigest()


def _client_token(pinned: LaunchReservation, purpose: str) -> str:
    return hashlib.sha256(
        f"aegentra.native.s2.v1:{pinned.org_id.hex}:{pinned.job_id.hex}:"
        f"{pinned.generation}:{purpose}".encode("ascii")
    ).hexdigest()


def _tags(pinned: LaunchReservation, role: str) -> list[dict[str, str]]:
    return [
        {"Key": "AegentraJob", "Value": str(pinned.job_id)},
        {"Key": "AegentraGeneration", "Value": str(pinned.generation)},
        {"Key": "AegentraRole", "Value": role},
    ]


def _plan(
    *, pinned: LaunchReservation, image: AmiCandidate,
    network: IsolationCandidate, region: str,
) -> LaunchPlan:
    """Build fixed requests for independent review, never execute them."""
    if (
        image.ami_id != pinned.ami_id
        or image.status != "EXTERNAL_PROVENANCE_AND_ISOLATION_DRILLS_REQUIRED"
        or network.status != "LIVE_ISOLATION_DRILLS_REQUIRED"
        or network.subnet_id != pinned.subnet_id
        or network.security_group_id != pinned.security_group_id
        or re.fullmatch(r"subnet-[0-9a-f]{8,17}", pinned.subnet_id) is None
        or re.fullmatch(r"sg-[0-9a-f]{8,17}", pinned.security_group_id) is None
        or re.fullmatch(r"[a-z]{2}(-gov)?-[a-z0-9-]+-[0-9]", region) is None
        or re.fullmatch(re.escape(region) + r"[a-z]", pinned.availability_zone) is None
        or not pinned.kms_key_arn.startswith(
            f"arn:aws:kms:{region}:{pinned.account_id}:key/"
        )
    ):
        raise LaunchPreflightRejected("physical launch pins are incomplete or changed")

    run_instances = {
        "ImageId": pinned.ami_id,
        "InstanceType": "t3.small",
        "MinCount": 1,
        "MaxCount": 1,
        "ClientToken": _client_token(pinned, "instance"),
        "Placement": {"AvailabilityZone": pinned.availability_zone},
        "NetworkInterfaces": [{
            "DeviceIndex": 0,
            "SubnetId": pinned.subnet_id,
            "Groups": [pinned.security_group_id],
            "AssociatePublicIpAddress": False,
            "DeleteOnTermination": True,
            "Ipv6AddressCount": 0,
        }],
        "MetadataOptions": {
            "HttpEndpoint": "disabled",
            "HttpTokens": "required",
            "HttpPutResponseHopLimit": 1,
            "HttpProtocolIpv6": "disabled",
            "InstanceMetadataTags": "disabled",
        },
        "InstanceInitiatedShutdownBehavior": "terminate",
        "EnclaveOptions": {"Enabled": False},
        "Monitoring": {"Enabled": False},
        "TagSpecifications": [
            {"ResourceType": "instance", "Tags": _tags(pinned, "GUEST")},
            {"ResourceType": "volume", "Tags": _tags(pinned, "ROOT")},
        ],
    }
    volumes = tuple({
        "AvailabilityZone": pinned.availability_zone,
        "Size": 1,
        "VolumeType": "gp3",
        "Encrypted": True,
        "KmsKeyId": pinned.kms_key_arn,
        "MultiAttachEnabled": False,
        "ClientToken": _client_token(pinned, role),
        "TagSpecifications": [
            {"ResourceType": "volume", "Tags": _tags(pinned, role)},
        ],
    } for role in ("INPUT_EBS", "OUTPUT_EBS"))
    return LaunchPlan(run_instances, volumes)


async def preflight_native_launch(
    *, sessions: async_sessionmaker[AsyncSession],
    ec2: Any, sts: Any, resolver: Any,
    org_id: UUID, job_id: UUID, generation: int,
    image_pin: AmiPin, network_pin: GuestNetworkPin,
) -> LaunchPlan:
    """DB pins -> read-only AWS preflight -> refreshed DB pins, no AWS write."""
    async with organization_session(sessions, org_id) as session:
        pinned = await load_reserved_launch(
            session, org_id=org_id, job_id=job_id,
            generation=generation, now=datetime.now(timezone.utc),
        )
    if (
        image_pin.analysis_account_id != pinned.account_id
        or image_pin.ami_id != pinned.ami_id
        or image_pin.kms_key_arn != pinned.kms_key_arn
        or network_pin.account_id != pinned.account_id
        or network_pin.subnet_id != pinned.subnet_id
        or network_pin.security_group_id != pinned.security_group_id
        or network_pin.availability_zone != pinned.availability_zone
    ):
        raise LaunchPreflightRejected("enrolled AMI/network pins differ from DB attempt")

    image = await asyncio.to_thread(
        verify_native_ami, ec2=ec2, sts=sts, pin=image_pin,
    )
    network = await asyncio.to_thread(
        evaluate_native_guest_network, ec2=ec2, sts=sts,
        resolver=resolver, pinned=network_pin, now=datetime.now(timezone.utc),
    )
    async with organization_session(sessions, org_id) as session:
        refreshed = await load_reserved_launch(
            session, org_id=org_id, job_id=job_id,
            generation=generation, now=datetime.now(timezone.utc),
        )
    if refreshed != pinned:
        raise LaunchPreflightRejected("fenced attempt changed during AWS preflight")
    return _plan(
        pinned=pinned, image=image, network=network, region=image_pin.region,
    )


def main() -> None:
    """Native read-only command prints only plan hash and NO-GO classification."""
    import boto3
    from botocore.config import Config

    org_id = UUID(os.environ["AEGENTRA_BRIDGE_ORG_ID"])
    job_id = UUID(os.environ["AEGENTRA_BRIDGE_JOB_ID"])
    generation = int(os.environ["AEGENTRA_BRIDGE_GENERATION"])
    region = os.environ["AEGENTRA_BRIDGE_AWS_REGION"]
    account_id = os.environ["AEGENTRA_ENROLLED_ANALYSIS_ACCOUNT_ID"]
    image_pin = AmiPin(
        analysis_account_id=account_id,
        ami_id=os.environ["AEGENTRA_ENROLLED_AMI_ID"],
        image_owner_id=os.environ["AEGENTRA_ENROLLED_IMAGE_OWNER_ID"],
        root_snapshot_id=os.environ["AEGENTRA_ENROLLED_ROOT_SNAPSHOT_ID"],
        snapshot_owner_id=os.environ["AEGENTRA_ENROLLED_SNAPSHOT_OWNER_ID"],
        kms_key_arn=os.environ["AEGENTRA_ENROLLED_EBS_KMS_KEY_ARN"],
        region=region,
    )
    network_pin = GuestNetworkPin(
        account_id=account_id,
        vpc_id=os.environ["AEGENTRA_ENROLLED_GUEST_VPC_ID"],
        subnet_id=os.environ["AEGENTRA_ENROLLED_GUEST_SUBNET_ID"],
        security_group_id=os.environ["AEGENTRA_ENROLLED_GUEST_SG_ID"],
        availability_zone=os.environ["AEGENTRA_ENROLLED_GUEST_AZ"],
    )
    config = Config(
        connect_timeout=2, read_timeout=3,
        retries={"max_attempts": 2, "mode": "standard"},
    )
    ec2 = boto3.client("ec2", region_name=region, config=config)
    sts = boto3.client("sts", region_name=region, config=config)
    resolver = boto3.client("route53resolver", region_name=region, config=config)
    engine = make_engine(os.environ["AEGENTRA_BRIDGE_DATABASE_URL"])

    async def run() -> LaunchPlan:
        try:
            return await preflight_native_launch(
                sessions=async_sessionmaker(engine, expire_on_commit=False),
                ec2=ec2, sts=sts, resolver=resolver,
                org_id=org_id, job_id=job_id, generation=generation,
                image_pin=image_pin, network_pin=network_pin,
            )
        finally:
            await engine.dispose()

    result = asyncio.run(run())
    print(json.dumps({
        "status": result.status,
        "job_id": str(job_id),
        "generation": generation,
        "plan_sha256": result.sha256(),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
