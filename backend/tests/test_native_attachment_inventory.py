"""Exact, read-only EC2/EBS inventory cannot imply guest execution trust."""
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from aegentra.bridge_custody import AttemptCustody, CustodyError
from aegentra.native_attachment_inventory import (
    LiveInventory, collect_live_inventory, verify_attachment_count,
    verify_termination_inventory,
)


class STS:
    account = "123456789012"

    def get_caller_identity(self):
        return {"Account": self.account}


class EC2:
    def __init__(self, expected):
        self.calls = []
        tags = [
            {"Key": "AegentraJob", "Value": str(expected.job_id)},
            {"Key": "AegentraGeneration", "Value": str(expected.generation)},
        ]
        self.instance = {
            "InstanceId": expected.instance_id, "ImageId": expected.ami_id,
            "State": {"Name": "running"}, "SubnetId": expected.subnet_id,
            "Placement": {"AvailabilityZone": expected.availability_zone},
            "MetadataOptions": {"HttpEndpoint": "disabled"},
            "SecurityGroups": [{"GroupId": expected.security_group_id}],
            "NetworkInterfaces": [{"SubnetId": expected.subnet_id}],
            "Tags": tags + [{"Key": "AegentraRole", "Value": "GUEST"}],
        }
        self.volumes = [{
            "VolumeId": vid, "AvailabilityZone": expected.availability_zone,
            "Encrypted": True, "KmsKeyId": expected.kms_key_arn,
            "VolumeType": "gp3", "Size": 1, "MultiAttachEnabled": False,
            "State": "available", "Attachments": [],
            "Tags": tags + [{"Key": "AegentraRole", "Value": role}],
        } for role, vid in (
            ("INPUT_EBS", expected.input_volume_id),
            ("OUTPUT_EBS", expected.output_volume_id),
        )]
        self.page = False

    def describe_instances(self, **kwargs):
        self.calls.append(("instance", kwargs))
        return {"Reservations": [{"Instances": [self.instance]}]}

    def describe_volumes(self, **kwargs):
        self.calls.append(("volumes", kwargs))
        return {
            "Volumes": self.volumes,
            **({"NextToken": "partial"} if self.page else {}),
        }


def fixture():
    expected = AttemptCustody(
        job_id=uuid4(), generation=1, account_id="123456789012",
        availability_zone="us-east-1a", instance_id="i-00000000000000001",
        ami_id="ami-00000000000000001",
        subnet_id="subnet-00000000000000001",
        security_group_id="sg-00000000000000001",
        input_volume_id="vol-00000000000000001",
        output_volume_id="vol-00000000000000002",
        kms_key_arn="arn:aws:kms:us-east-1:123456789012:key/test",
    )
    return expected, EC2(expected), STS()


def set_attached(ec2, expected, count):
    for i in range(count):
        ec2.volumes[i]["State"] = "in-use"
        ec2.volumes[i]["Attachments"] = [{
            "InstanceId": expected.instance_id,
            "Device": ("/dev/sdf", "/dev/sdg")[i],
            "State": "attached",
        }]


def test_native_exact_two_devices_require_read_only_inventory():
    expected, ec2, sts = fixture()
    for stage in (0, 1, 2):
        set_attached(ec2, expected, stage)
        observed = collect_live_inventory(ec2=ec2, sts=sts, expected=expected)
        verify_attachment_count(expected=expected, observed=observed, attached=stage)
    assert set(x[0] for x in ec2.calls) == {"instance", "volumes"}


@pytest.mark.parametrize("alter", [
    "wrong_account", "wrong_ami", "imds", "public_ip", "bad_tags",
    "wrong_instance", "wrong_device", "incomplete", "wrong_kms",
    "already_attached", "wrong_role", "wrong_az",
])
def test_unsafe_or_ambiguous_inventory_rejected(alter):
    expected, ec2, sts = fixture()
    if alter == "wrong_account":
        sts.account = "000000000000"
    elif alter == "wrong_ami":
        ec2.instance["ImageId"] = "ami-00000000000000002"
    elif alter == "imds":
        ec2.instance["MetadataOptions"]["HttpEndpoint"] = "enabled"
    elif alter == "public_ip":
        ec2.instance["PublicIpAddress"] = "192.0.2.5"
    elif alter == "bad_tags":
        ec2.instance["Tags"][0]["Value"] = "different"
    elif alter == "wrong_instance":
        set_attached(ec2, expected, 1)
        ec2.volumes[0]["Attachments"][0]["InstanceId"] = "i-00000000000000002"
    elif alter == "wrong_device":
        set_attached(ec2, expected, 1)
        ec2.volumes[0]["Attachments"][0]["Device"] = "/dev/sdz"
    elif alter == "incomplete":
        ec2.page = True
    elif alter == "wrong_kms":
        ec2.volumes[0]["KmsKeyId"] = "arn:aws:kms:us-east-1:123456789012:key/wrong"
    elif alter == "already_attached":
        set_attached(ec2, expected, 2)
    elif alter == "wrong_role":
        ec2.volumes[0]["Tags"][-1]["Value"] = "OUTPUT_EBS"
    else:
        ec2.volumes[0]["AvailabilityZone"] = "us-east-1b"
    with pytest.raises(CustodyError):
        observed = collect_live_inventory(ec2=ec2, sts=sts, expected=expected)
        verify_attachment_count(expected=expected, observed=observed, attached=1)


def test_stale_snapshots_rejected():
    expected, ec2, sts = fixture()
    observed = collect_live_inventory(ec2=ec2, sts=sts, expected=expected)
    stale = LiveInventory(
        observed.account_id, datetime(2020, 1, 1, tzinfo=timezone.utc),
        observed.instance, observed.volumes,
    )
    with pytest.raises(CustodyError):
        verify_attachment_count(expected=expected, observed=stale, attached=0)


def test_termination_requires_exact_attachment_ownership():
    expected, ec2, sts = fixture()
    set_attached(ec2, expected, 2)
    observed = collect_live_inventory(ec2=ec2, sts=sts, expected=expected)
    verify_termination_inventory(expected=expected, observed=observed)
    ec2.volumes[1]["Attachments"][0]["InstanceId"] = "i-00000000000000002"
    observed = collect_live_inventory(ec2=ec2, sts=sts, expected=expected)
    with pytest.raises(CustodyError):
        verify_termination_inventory(expected=expected, observed=observed)


def test_termination_allows_exact_partial_attachment_for_failed_attempt_cleanup():
    expected, ec2, sts = fixture()
    set_attached(ec2, expected, 1)
    observed = collect_live_inventory(ec2=ec2, sts=sts, expected=expected)
    verify_termination_inventory(expected=expected, observed=observed)
    assert observed.instance["InstanceId"] == expected.instance_id
