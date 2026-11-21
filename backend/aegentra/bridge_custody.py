"""Bridge-side EC2 custody checks, using fresh AWS responses and DB-pinned IDs.

Resource tags and control-plane responses are *not* proof of guest network
isolation or human approval. This check is necessary before reading detached
raw output; live IAM, routing, IMDS and guest reachability drills remain P0.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID


class CustodyError(ValueError):
    pass


@dataclass(frozen=True)
class AttemptCustody:
    job_id: UUID
    generation: int
    account_id: str
    availability_zone: str
    instance_id: str
    subnet_id: str
    security_group_id: str
    input_volume_id: str
    output_volume_id: str
    kms_key_arn: str


@dataclass(frozen=True)
class DetachedInventory:
    """One timestamped, account-pinned read-only EC2/EBS inventory pass."""

    account_id: str
    observed_at: datetime
    instances: tuple[dict[str, Any], ...]
    volumes: tuple[dict[str, Any], ...]


def _tags(resource: dict) -> dict[str, str]:
    entries = resource.get("Tags")
    if not isinstance(entries, list):
        raise CustodyError("missing resource ownership tags")
    values: dict[str, str] = {}
    for item in entries:
        if not isinstance(item, dict) or not isinstance(item.get("Key"), str):
            raise CustodyError("malformed AWS tags")
        key, value = item["Key"], item.get("Value")
        if not isinstance(value, str) or key in values:
            raise CustodyError("duplicate or invalid AWS tag")
        values[key] = value
    return values


def _assert_pinned_tags(resource: dict, expected: AttemptCustody) -> None:
    tags = _tags(resource)
    if (
        tags.get("AegentraJob") != str(expected.job_id)
        or tags.get("AegentraGeneration") != str(expected.generation)
    ):
        raise CustodyError("resource does not match recorded job generation")


def verify_detached_attempt(
    *,
    expected: AttemptCustody,
    observed_account_id: str,
    instances: list[dict[str, Any]],
    volumes: list[dict[str, Any]],
) -> None:
    """Fail closed unless both EBS volumes are detached after VM termination.

    The bridge must fetch fresh describe_instances/describe_volumes using its
    independent, read-only inventory credentials and compare a durable record.
    """
    if expected.generation < 1 or expected.input_volume_id == expected.output_volume_id:
        raise CustodyError("invalid recorded physical attempt")
    if observed_account_id != expected.account_id:
        raise CustodyError("wrong AWS account")
    if len(instances) != 1 or len(volumes) != 2:
        raise CustodyError("missing, duplicated or ambiguous AWS resources")
    instance = instances[0]
    _assert_pinned_tags(instance, expected)
    if (
        instance.get("InstanceId") != expected.instance_id
        or instance.get("State", {}).get("Name") != "terminated"
        or instance.get("SubnetId") != expected.subnet_id
        or instance.get("Placement", {}).get("AvailabilityZone") != expected.availability_zone
        or instance.get("MetadataOptions", {}).get("HttpEndpoint") != "disabled"
        or instance.get("IamInstanceProfile") is not None
        or instance.get("PublicIpAddress") is not None
        or instance.get("Ipv6Address") is not None
    ):
        raise CustodyError("instance identity or termination boundary mismatch")
    groups = instance.get("SecurityGroups")
    if not isinstance(groups, list) or {
        group.get("GroupId") for group in groups
    } != {expected.security_group_id}:
        raise CustodyError("wrong guest security group")
    nics = instance.get("NetworkInterfaces")
    if not isinstance(nics, list) or len(nics) != 1:
        raise CustodyError("unexpected guest network interfaces")
    nic = nics[0]
    if (
        nic.get("SubnetId") != expected.subnet_id
        or nic.get("Association")
        or nic.get("Ipv6Addresses")
    ):
        raise CustodyError("unexpected network interface or public association")

    by_id = {volume.get("VolumeId"): volume for volume in volumes}
    if set(by_id) != {expected.input_volume_id, expected.output_volume_id}:
        raise CustodyError("EBS IDs differ from recorded attempt")
    for volume in volumes:
        _assert_pinned_tags(volume, expected)
        if (
            volume.get("State") != "available"
            or volume.get("Attachments") != []
            or volume.get("AvailabilityZone") != expected.availability_zone
            or volume.get("Encrypted") is not True
            or volume.get("KmsKeyId") != expected.kms_key_arn
        ):
            raise CustodyError("EBS volume remains attached or is not qualified")


def verify_two_pass_cleanup(
    *, expected: AttemptCustody, first: DetachedInventory,
    second: DetachedInventory, now: datetime,
) -> None:
    """Require two fresh, time-separated inventories before trusting detach.

    The independent bridge obtains each read-only snapshot separately. These
    AWS control-plane checks are not guest network-isolation qualification.
    """
    timestamps = (first.observed_at, second.observed_at, now)
    if any(tz.tzinfo is None or tz.utcoffset() is None for tz in timestamps):
        raise CustodyError("trusted UTC-aware detach inventory clocks required")
    start, end, checked = (t.astimezone(timezone.utc) for t in timestamps)
    if (
        end - start < timedelta(seconds=30)
        or end - start > timedelta(minutes=5)
        or end > checked
        or checked - end > timedelta(seconds=60)
        or first.account_id != expected.account_id
        or second.account_id != expected.account_id
    ):
        raise CustodyError("detached inventory passes are not fresh and separated")
    for snapshot in (first, second):
        verify_detached_attempt(
            expected=expected, observed_account_id=snapshot.account_id,
            instances=list(snapshot.instances), volumes=list(snapshot.volumes),
        )
