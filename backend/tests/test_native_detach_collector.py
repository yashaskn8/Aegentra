"""Native EC2/EBS detached inventory is exact, bounded, read-only."""
from uuid import uuid4

import pytest

from aegentra.bridge_custody import AttemptCustody, CustodyError
from aegentra.native_detach_collector import collect_detached_inventory


class STS:
    def __init__(self):
        self.account = "123456789012"
        self.calls = 0

    def get_caller_identity(self):
        self.calls += 1
        return {"Account": self.account}


class EC2:
    def __init__(self, expected):
        self.calls = []
        self.fail_on = None
        tags = [
            {"Key": "AegentraJob", "Value": str(expected.job_id)},
            {"Key": "AegentraGeneration", "Value": str(expected.generation)},
        ]
        self.instance = {
            "InstanceId": expected.instance_id,
            "ImageId": expected.ami_id,
            "State": {"Name": "terminated"},
            "SubnetId": expected.subnet_id,
            "Placement": {"AvailabilityZone": expected.availability_zone},
            "MetadataOptions": {"HttpEndpoint": "disabled"},
            "SecurityGroups": [{"GroupId": expected.security_group_id}],
            "NetworkInterfaces": [{"SubnetId": expected.subnet_id}],
            "Tags": tags,
        }
        self.volumes = [
            {
                "VolumeId": volume_id, "State": "available", "Attachments": [],
                "AvailabilityZone": expected.availability_zone,
                "Encrypted": True, "KmsKeyId": expected.kms_key_arn,
                "Tags": tags,
            }
            for volume_id in (expected.input_volume_id, expected.output_volume_id)
        ]
        self.instance_pagination = None
        self.volume_pagination = None

    def describe_instances(self, **kwargs):
        self.calls.append(("describe_instances", kwargs))
        if self.fail_on == "instances":
            raise RuntimeError("EC2 unavailable")
        return {
            "Reservations": [{"Instances": [self.instance]}],
            "NextToken": self.instance_pagination,
        }

    def describe_volumes(self, **kwargs):
        self.calls.append(("describe_volumes", kwargs))
        if self.fail_on == "volumes":
            raise RuntimeError("EBS unavailable")
        return {"Volumes": self.volumes, "NextToken": self.volume_pagination}


def setup():
    expected = AttemptCustody(
        job_id=uuid4(), generation=2, account_id="123456789012",
        availability_zone="us-east-1a",
        instance_id="i-00000000000000001",
        ami_id="ami-00000000000000001",
        subnet_id="subnet-deny", security_group_id="sg-deny",
        input_volume_id="vol-00000000000000001",
        output_volume_id="vol-00000000000000002",
        kms_key_arn="arn:aws:kms:us-east-1:123456789012:key/test",
    )
    return expected, EC2(expected), STS()


def test_collects_exact_pinned_resources_without_aws_mutations():
    expected, ec2, sts = setup()
    observed = collect_detached_inventory(ec2=ec2, sts=sts, expected=expected)
    assert observed.account_id == expected.account_id
    assert observed.observed_at.utcoffset().total_seconds() == 0
    assert len(observed.instances) == 1
    assert len(observed.volumes) == 2
    assert sts.calls == 1
    assert ec2.calls == [
        ("describe_instances", {"InstanceIds": [expected.instance_id]}),
        ("describe_volumes", {"VolumeIds": [
            expected.input_volume_id, expected.output_volume_id,
        ]}),
    ]


def test_rejects_wrong_account_before_any_ec2_call():
    expected, ec2, sts = setup()
    sts.account = "000000000000"
    with pytest.raises(CustodyError, match="account differs"):
        collect_detached_inventory(ec2=ec2, sts=sts, expected=expected)
    assert ec2.calls == []


@pytest.mark.parametrize("tamper", [
    "running", "attached", "unexpected_volume", "duplicate_volumes",
    "instance_page", "volume_page", "missing_instance", "missing_volume",
    "unauthorized_instance", "unauthorized_volume", "wrong_tag",
    "public_ip", "profile", "metadata", "wrong_ami",
])
def test_tampered_or_unavailable_inventory_never_produces_custody(tamper):
    expected, ec2, sts = setup()
    if tamper == "running":
        ec2.instance["State"]["Name"] = "running"
    elif tamper == "attached":
        ec2.volumes[0]["Attachments"] = [{"InstanceId": expected.instance_id}]
    elif tamper == "unexpected_volume":
        ec2.volumes[1]["VolumeId"] = "vol-another"
    elif tamper == "duplicate_volumes":
        ec2.volumes[1]["VolumeId"] = ec2.volumes[0]["VolumeId"]
    elif tamper == "instance_page":
        ec2.instance_pagination = "unread"
    elif tamper == "volume_page":
        ec2.volume_pagination = "unread"
    elif tamper == "missing_instance":
        ec2.instance = None
    elif tamper == "missing_volume":
        ec2.volumes.pop()
    elif tamper == "unauthorized_instance":
        ec2.fail_on = "instances"
    elif tamper == "unauthorized_volume":
        ec2.fail_on = "volumes"
    elif tamper == "wrong_tag":
        ec2.instance["Tags"][0]["Value"] = "not-the-job"
    elif tamper == "public_ip":
        ec2.instance["PublicIpAddress"] = "192.0.2.1"
    elif tamper == "profile":
        ec2.instance["IamInstanceProfile"] = {"Arn": "unauthorized"}
    elif tamper == "wrong_ami":
        ec2.instance["ImageId"] = "ami-00000000000000009"
    else:
        ec2.instance["MetadataOptions"]["HttpEndpoint"] = "enabled"
    with pytest.raises(CustodyError):
        collect_detached_inventory(ec2=ec2, sts=sts, expected=expected)
