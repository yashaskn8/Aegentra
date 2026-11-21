"""Fresh, read-only AWS evidence for exact disposable EBS attachment.

An AWS inventory check does not prove raw guest isolation, toolchain
provenance, guest device paths, or safe execution. No AWS mutation here.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from aegentra.bridge_custody import (
    AttemptCustody, CustodyError, _assert_pinned_tags,
)


@dataclass(frozen=True)
class LiveInventory:
    account_id: str
    observed_at: datetime
    instance: dict[str, Any]
    volumes: tuple[dict[str, Any], dict[str, Any]]


def _one_instance(response: Any) -> dict[str, Any]:
    if (
        not isinstance(response, dict) or response.get("NextToken")
        or not isinstance(response.get("Reservations"), list)
        or len(response["Reservations"]) != 1
        or not isinstance(response["Reservations"][0], dict)
    ):
        raise CustodyError("missing, partial or ambiguous live instance inventory")
    instances = response["Reservations"][0].get("Instances")
    if not isinstance(instances, list) or len(instances) != 1 or not isinstance(instances[0], dict):
        raise CustodyError("untrusted native guest inventory")
    return instances[0]


def collect_live_inventory(
    *, ec2: Any, sts: Any, expected: AttemptCustody,
) -> LiveInventory:
    """Request only journal-pinned physical IDs, reject incomplete AWS reads."""
    start = datetime.now(timezone.utc)
    try:
        account = sts.get_caller_identity()["Account"]
    except Exception as exc:
        raise CustodyError("cannot identify live AWS inventory principal") from exc
    if account != expected.account_id:
        raise CustodyError("live inventory AWS account mismatch")
    try:
        instance = _one_instance(ec2.describe_instances(
            InstanceIds=[expected.instance_id],
        ))
        response = ec2.describe_volumes(VolumeIds=[
            expected.input_volume_id, expected.output_volume_id,
        ])
        if (
            not isinstance(response, dict) or response.get("NextToken")
            or not isinstance(response.get("Volumes"), list)
            or len(response["Volumes"]) != 2
            or any(not isinstance(v, dict) for v in response["Volumes"])
        ):
            raise CustodyError("missing, partial or ambiguous EBS inventory")
        volumes = tuple(response["Volumes"])
    except CustodyError:
        raise
    except Exception as exc:
        raise CustodyError("native live AWS inventory unavailable") from exc
    finished = datetime.now(timezone.utc)
    if finished < start or finished - start > timedelta(seconds=10):
        raise CustodyError("native live inventory freshness budget exceeded")
    result = LiveInventory(account, finished, instance, volumes)
    verify_live_inventory(expected=expected, observed=result)
    return result


def verify_live_inventory(
    *, expected: AttemptCustody, observed: LiveInventory,
) -> None:
    """Check only strictly owned, encrypted and physically pinned resources."""
    now = datetime.now(timezone.utc)
    if (
        observed.observed_at.tzinfo is None
        or observed.account_id != expected.account_id
        or observed.observed_at > now
        or now - observed.observed_at > timedelta(seconds=15)
    ):
        raise CustodyError("live AWS snapshot stale or from wrong account")
    instance = observed.instance
    _assert_pinned_tags(instance, expected)
    if (
        instance.get("InstanceId") != expected.instance_id
        or instance.get("ImageId") != expected.ami_id
        or instance.get("State", {}).get("Name") not in {
            "pending", "running", "stopping", "stopped", "shutting-down",
        }
        or instance.get("SubnetId") != expected.subnet_id
        or instance.get("Placement", {}).get("AvailabilityZone") != expected.availability_zone
        or instance.get("MetadataOptions", {}).get("HttpEndpoint") != "disabled"
        or instance.get("IamInstanceProfile") is not None
        or instance.get("PublicIpAddress") is not None
        or instance.get("Ipv6Address") is not None
    ):
        raise CustodyError("live guest identity or isolation mismatch")
    groups = instance.get("SecurityGroups")
    interfaces = instance.get("NetworkInterfaces")
    if (
        not isinstance(groups, list) or len(groups) != 1
        or groups[0].get("GroupId") != expected.security_group_id
        or not isinstance(interfaces, list) or len(interfaces) != 1
        or interfaces[0].get("SubnetId") != expected.subnet_id
        or interfaces[0].get("Association") or interfaces[0].get("Ipv6Addresses")
    ):
        raise CustodyError("live guest networking is not pinned")
    if len(observed.volumes) != 2:
        raise CustodyError("live EBS inventory incomplete")
    ids = {v.get("VolumeId") for v in observed.volumes}
    if ids != {expected.input_volume_id, expected.output_volume_id}:
        raise CustodyError("live EBS identities differ from physical journal")
    for volume in observed.volumes:
        _assert_pinned_tags(volume, expected)
        if (
            volume.get("AvailabilityZone") != expected.availability_zone
            or volume.get("Encrypted") is not True
            or volume.get("KmsKeyId") != expected.kms_key_arn
            or volume.get("VolumeType") != "gp3"
            or volume.get("Size") != 1
            or volume.get("MultiAttachEnabled") is not False
            or volume.get("State") not in {"available", "in-use"}
            or not isinstance(volume.get("Attachments"), list)
        ):
            raise CustodyError("EBS volume encryption, size or attachment state unsafe")
        role = "INPUT_EBS" if volume["VolumeId"] == expected.input_volume_id else "OUTPUT_EBS"
        tags = volume["Tags"]
        if len([x for x in tags if x.get("Key") == "AegentraRole" and x.get("Value") == role]) != 1:
            raise CustodyError("EBS role not pinned")


def verify_attachment_count(
    *, expected: AttemptCustody, observed: LiveInventory, attached: int,
) -> None:
    """Accept only zero/one/two exact raw-device attachments in that order."""
    verify_live_inventory(expected=expected, observed=observed)
    if attached not in {0, 1, 2} or observed.instance["State"]["Name"] != "running":
        raise CustodyError("native guest not running or attachment stage unsupported")
    by_id = {v["VolumeId"]: v for v in observed.volumes}
    for i, (volume_id, device) in enumerate((
        (expected.input_volume_id, "/dev/sdf"),
        (expected.output_volume_id, "/dev/sdg"),
    )):
        volume = by_id[volume_id]
        if i < attached:
            wanted = [{
                "InstanceId": expected.instance_id, "Device": device, "State": "attached",
            }]
            attachments = volume["Attachments"]
            if (
                len(attachments) != 1
                or not isinstance(attachments[0], dict)
                or any(attachments[0].get(k) != v for k, v in wanted[0].items())
                or volume["State"] != "in-use"
            ):
                raise CustodyError("raw EBS attachment missing or has wrong instance/device")
        elif volume["Attachments"] != [] or volume["State"] != "available":
            raise CustodyError("raw EBS volume already attached or unavailable")


def verify_termination_inventory(
    *, expected: AttemptCustody, observed: LiveInventory,
) -> None:
    """Allow termination only for a known live guest and exact raw attachments.

    A shutdown request does not prove that the instance has terminated or
    that EBS has detached; the independent two-pass detach oracle does that.
    """
    verify_live_inventory(expected=expected, observed=observed)
    if observed.instance["State"]["Name"] not in {
        "pending", "running", "stopping", "stopped", "shutting-down",
    }:
        raise CustodyError("physical termination candidate untrusted")
    by_id = {v["VolumeId"]: v for v in observed.volumes}
    for volume_id, device in (
        (expected.input_volume_id, "/dev/sdf"),
        (expected.output_volume_id, "/dev/sdg"),
    ):
        volume = by_id[volume_id]
        attachments = volume["Attachments"]
        if volume["State"] == "available":
            if attachments != []:
                raise CustodyError("available EBS has an unexpected attachment")
        elif (
            volume["State"] != "in-use"
            or len(attachments) != 1
            or not isinstance(attachments[0], dict)
            or attachments[0].get("InstanceId") != expected.instance_id
            or attachments[0].get("Device") != device
            or attachments[0].get("State") not in {
                "attaching", "attached", "detaching",
            }
        ):
            raise CustodyError("raw EBS volume is not attached to the pinned guest")
