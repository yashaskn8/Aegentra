"""Exact AWS NotFound is required; API failure is never evidence of deletion."""
from datetime import datetime, timezone

import pytest

from aegentra.bridge_disposal import DisposalRejected
from aegentra.disposal_collector import collect_deleted_inventory


class AwsFailure(Exception):
    def __init__(self, code):
        self.response = {"Error": {"Code": code}}
        super().__init__(code)


class Sts:
    account = "123456789012"

    def get_caller_identity(self):
        return {"Account": self.account}


class Ec2:
    def __init__(self):
        self.instance = "terminated"
        self.volume = "not-found"
        self.instance_queries = []
        self.volume_queries = []

    def describe_instances(self, **kwargs):
        self.instance_queries.append(kwargs)
        if self.instance == "not-found":
            raise AwsFailure("InvalidInstanceID.NotFound")
        if self.instance == "access-denied":
            raise AwsFailure("UnauthorizedOperation")
        if self.instance == "malformed":
            return {"Reservations": []}
        return {"Reservations": [{
            "Instances": [{
                "InstanceId": kwargs["InstanceIds"][0],
                "State": {"Name": self.instance},
            }],
        }]}

    def describe_volumes(self, **kwargs):
        self.volume_queries.append(kwargs)
        if self.volume == "not-found":
            raise AwsFailure("InvalidVolume.NotFound")
        if self.volume == "access-denied":
            raise AwsFailure("UnauthorizedOperation")
        return {"Volumes": [{
            "VolumeId": kwargs["VolumeIds"][0],
            "State": self.volume,
        }]}


def collect(ec2=None, sts=None):
    return collect_deleted_inventory(
        ec2=ec2 or Ec2(), sts=sts or Sts(),
        expected_account="123456789012",
        instance_id="i-00000000000000001",
        input_volume_id="vol-00000000000000001",
        output_volume_id="vol-00000000000000002",
        observed_at=datetime(2026, 11, 20, tzinfo=timezone.utc),
    )


def test_two_volumes_must_return_explicit_not_found():
    ec2 = Ec2()
    result = collect(ec2)
    assert result.instance_state == "terminated"
    assert result.volume_states == {
        "vol-00000000000000001": "not-found",
        "vol-00000000000000002": "not-found",
    }
    assert ec2.instance_queries == [{
        "InstanceIds": ["i-00000000000000001"],
    }]
    assert ec2.volume_queries == [
        {"VolumeIds": ["vol-00000000000000001"]},
        {"VolumeIds": ["vol-00000000000000002"]},
    ]


def test_missing_instance_after_termination_is_valid():
    ec2 = Ec2()
    ec2.instance = "not-found"
    assert collect(ec2).instance_state == "not-found"


@pytest.mark.parametrize("kind", [
    "running", "stopping", "access-denied", "malformed",
])
def test_untrusted_instance_result_denied(kind):
    ec2 = Ec2()
    ec2.instance = kind
    with pytest.raises(DisposalRejected):
        collect(ec2)


@pytest.mark.parametrize("kind", [
    "available", "in-use", "deleting", "access-denied",
])
def test_existing_or_ambiguous_ebs_result_denied(kind):
    ec2 = Ec2()
    ec2.volume = kind
    with pytest.raises(DisposalRejected):
        collect(ec2)


def test_wrong_aws_account_denied():
    sts = Sts()
    sts.account = "000000000000"
    with pytest.raises(DisposalRejected):
        collect(sts=sts)
