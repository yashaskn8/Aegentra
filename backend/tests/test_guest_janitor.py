"""Janitor must not delete anything unless exact custody was qualified."""
from uuid import uuid4

import pytest

from aegentra.bridge_custody import AttemptCustody, CustodyError
from aegentra.guest_janitor import JanitorUnknown, request_detached_volume_deletion


class EC2:
    def __init__(self):
        self.deleted = []
        self.fail_on = None

    def delete_volume(self, **kwargs):
        self.deleted.append(kwargs["VolumeId"])
        if kwargs["VolumeId"] == self.fail_on:
            raise OSError("simulated EBS outcome unknown")
        return {}


def fixture():
    job = uuid4()
    expected = AttemptCustody(
        job_id=job, generation=2, account_id="123456789012",
        availability_zone="us-east-1a",
        instance_id="i-00000000000000001",
        subnet_id="subnet-closed", security_group_id="sg-deny",
        input_volume_id="vol-00000000000000001",
        output_volume_id="vol-00000000000000002",
        kms_key_arn="arn:aws:kms:us-east-1:123456789012:key/test",
    )
    tags = [
        {"Key": "AegentraJob", "Value": str(job)},
        {"Key": "AegentraGeneration", "Value": "2"},
    ]
    instance = {
        "InstanceId": expected.instance_id,
        "State": {"Name": "terminated"},
        "SubnetId": expected.subnet_id,
        "Placement": {"AvailabilityZone": expected.availability_zone},
        "MetadataOptions": {"HttpEndpoint": "disabled"},
        "SecurityGroups": [{"GroupId": expected.security_group_id}],
        "NetworkInterfaces": [{"SubnetId": expected.subnet_id}],
        "Tags": tags,
    }
    volumes = [{
        "VolumeId": vid, "State": "available", "Attachments": [],
        "Encrypted": True,
        "AvailabilityZone": expected.availability_zone,
        "KmsKeyId": expected.kms_key_arn, "Tags": tags,
    } for vid in (expected.input_volume_id, expected.output_volume_id)]
    return expected, instance, volumes


def call(client, expected, instance, volumes, account="123456789012"):
    return request_detached_volume_deletion(
        ec2=client, expected=expected, observed_account=account,
        terminated_instances=[instance], detached_volumes=volumes,
    )


def test_exact_two_volumes_requested_only_after_terminated_detached_proof():
    expected, instance, volumes = fixture()
    client = EC2()
    result = call(client, expected, instance, volumes)
    assert client.deleted == [
        expected.input_volume_id, expected.output_volume_id
    ]
    assert result.status == "DELETION_REQUESTED_PENDING_INDEPENDENT_INVENTORY"


@pytest.mark.parametrize("tamper", [
    "wrong_account", "running", "attached", "wrong_generation",
    "unencrypted", "extra_volume",
])
def test_unqualified_inventory_never_triggers_deletion(tamper):
    expected, instance, volumes = fixture()
    if tamper == "running":
        instance["State"]["Name"] = "running"
    elif tamper == "attached":
        volumes[0]["Attachments"] = [{"InstanceId": expected.instance_id}]
    elif tamper == "wrong_generation":
        instance["Tags"][1]["Value"] = "1"
    elif tamper == "unencrypted":
        volumes[0]["Encrypted"] = False
    elif tamper == "extra_volume":
        volumes.append(dict(volumes[0], VolumeId="vol-00000000000000003"))
    client = EC2()
    with pytest.raises(CustodyError):
        call(
            client, expected, instance, volumes,
            account="000000000000" if tamper == "wrong_account" else "123456789012",
        )
    assert client.deleted == []


def test_failed_second_delete_is_unknown_and_not_success():
    expected, instance, volumes = fixture()
    client = EC2()
    client.fail_on = expected.output_volume_id
    with pytest.raises(JanitorUnknown):
        call(client, expected, instance, volumes)
    assert client.deleted == [expected.input_volume_id, expected.output_volume_id]
