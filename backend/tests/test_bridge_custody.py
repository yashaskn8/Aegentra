from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from aegentra.bridge_custody import (
    AttemptCustody, CustodyError, DetachedInventory,
    verify_detached_attempt, verify_two_pass_cleanup,
)


def fixture():
    record = AttemptCustody(
        job_id=uuid4(), generation=3, account_id="123456789012",
        availability_zone="us-east-1a", instance_id="i-0123",
        subnet_id="subnet-123", security_group_id="sg-123",
        input_volume_id="vol-111", output_volume_id="vol-222",
        kms_key_arn="arn:aws:kms:us-east-1:123456789012:key/example",
    )
    tags = [
        {"Key": "AegentraJob", "Value": str(record.job_id)},
        {"Key": "AegentraGeneration", "Value": "3"},
    ]
    instance = {
        "InstanceId": record.instance_id,
        "State": {"Name": "terminated"},
        "SubnetId": record.subnet_id,
        "Placement": {"AvailabilityZone": record.availability_zone},
        "MetadataOptions": {"HttpEndpoint": "disabled"},
        "SecurityGroups": [{"GroupId": record.security_group_id}],
        "NetworkInterfaces": [{"SubnetId": record.subnet_id, "Ipv6Addresses": []}],
        "Tags": tags,
    }
    volumes = [
        {
            "VolumeId": vol, "State": "available", "Attachments": [],
            "AvailabilityZone": record.availability_zone, "Encrypted": True,
            "KmsKeyId": record.kms_key_arn, "Tags": tags,
        }
        for vol in (record.input_volume_id, record.output_volume_id)
    ]
    return record, instance, volumes


def test_detached_native_attempt_is_structurally_valid() -> None:
    record, instance, volumes = fixture()
    verify_detached_attempt(
        expected=record, observed_account_id=record.account_id,
        instances=[instance], volumes=volumes,
    )
    now = datetime.now(timezone.utc)
    first = DetachedInventory(record.account_id, now - timedelta(seconds=40),
                              (instance,), tuple(volumes))
    second = replace(first, observed_at=now - timedelta(seconds=5))
    verify_two_pass_cleanup(
        expected=record, first=first, second=second, now=now,
    )


@pytest.mark.parametrize("change", [
    "public", "profile", "metadata", "state", "az", "sg", "network",
    "attached", "unencrypted", "kms", "tags", "volume", "account",
])
def test_bridge_fails_closed_on_physical_mismatch(change: str) -> None:
    record, instance, volumes = fixture()
    account = record.account_id
    if change == "public":
        instance["PublicIpAddress"] = "192.0.2.1"
    elif change == "profile":
        instance["IamInstanceProfile"] = {"Arn": "arn:aws:iam::x:instance-profile/x"}
    elif change == "metadata":
        instance["MetadataOptions"]["HttpEndpoint"] = "enabled"
    elif change == "state":
        instance["State"]["Name"] = "running"
    elif change == "az":
        instance["Placement"]["AvailabilityZone"] = "us-east-1b"
    elif change == "sg":
        instance["SecurityGroups"] = [{"GroupId": "sg-other"}]
    elif change == "network":
        instance["NetworkInterfaces"].append({"SubnetId": "other"})
    elif change == "attached":
        volumes[0]["Attachments"] = [{"InstanceId": record.instance_id}]
    elif change == "unencrypted":
        volumes[0]["Encrypted"] = False
    elif change == "kms":
        volumes[0]["KmsKeyId"] = "wrong"
    elif change == "tags":
        volumes[0]["Tags"] = [{"Key": "AegentraJob", "Value": "unrelated"}]
    elif change == "volume":
        volumes[0]["VolumeId"] = "vol-unexpected"
    else:
        account = "000000000000"
    with pytest.raises(CustodyError):
        verify_detached_attempt(
            expected=record, observed_account_id=account,
            instances=[instance], volumes=volumes,
        )


def test_two_pass_detects_late_rebind() -> None:
    record, instance, volumes = fixture()
    rebound = [dict(v) for v in volumes]
    rebound[1]["Attachments"] = [{"InstanceId": "i-else"}]
    now = datetime.now(timezone.utc)
    first = DetachedInventory(record.account_id, now - timedelta(seconds=40),
                              (instance,), tuple(volumes))
    second = replace(first, observed_at=now - timedelta(seconds=5),
                     volumes=tuple(rebound))
    with pytest.raises(CustodyError):
        verify_two_pass_cleanup(
            expected=record, first=first, second=second, now=now,
        )


@pytest.mark.parametrize("change", [
    "same_time", "out_of_order", "too_far", "stale", "future",
    "wrong_account", "naive_time",
])
def test_two_pass_rejects_untrusted_time_and_account(change: str) -> None:
    record, instance, volumes = fixture()
    now = datetime(2026, 11, 21, 12, tzinfo=timezone.utc)
    first = DetachedInventory(record.account_id, now - timedelta(seconds=40),
                              (instance,), tuple(volumes))
    second = replace(first, observed_at=now - timedelta(seconds=5))
    if change == "same_time":
        second = replace(second, observed_at=first.observed_at)
    elif change == "out_of_order":
        second = replace(second, observed_at=first.observed_at - timedelta(seconds=1))
    elif change == "too_far":
        first = replace(first, observed_at=now - timedelta(minutes=10))
    elif change == "stale":
        second = replace(second, observed_at=now - timedelta(minutes=2))
    elif change == "future":
        second = replace(second, observed_at=now + timedelta(seconds=1))
    elif change == "wrong_account":
        second = replace(second, account_id="000000000000")
    else:
        first = replace(first, observed_at=first.observed_at.replace(tzinfo=None))
    with pytest.raises(CustodyError):
        verify_two_pass_cleanup(
            expected=record, first=first, second=second, now=now,
        )
