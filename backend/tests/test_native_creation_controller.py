"""Simulated AWS only: no cloud mutations, no retries after ambiguity."""
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from aegentra import native_creation_controller as controller
from aegentra.bridge_journal import LaunchReservation
from aegentra.native_ami_preflight import AmiCandidate
from aegentra.native_isolation_guard import IsolationCandidate
from aegentra.native_launch_preflight import _plan


class FakeEC2:
    def __init__(self, pin):
        self.calls = []
        self.pin = pin
        self.fail_number = 0
        self.malformed_number = 0

    def create_volume(self, **kwargs):
        self.calls.append(("create_volume", kwargs))
        index = len(self.calls)
        if index == self.fail_number:
            raise TimeoutError("ambiguous EC2 timeout")
        if index == self.malformed_number:
            return {"VolumeId": "vol-unknown"}
        return {
            "VolumeId": f"vol-{index:017x}",
            "AvailabilityZone": self.pin.availability_zone,
            "Encrypted": True, "KmsKeyId": self.pin.kms_key_arn,
            "VolumeType": "gp3", "Size": 1, "State": "creating",
        }

    def run_instances(self, **kwargs):
        self.calls.append(("run_instances", kwargs))
        index = len(self.calls)
        if index == self.fail_number:
            raise TimeoutError("ambiguous run instances timeout")
        if index == self.malformed_number:
            return {"Instances": [{"InstanceId": "i-00000000000000003"}]}
        return {"Instances": [{
            "InstanceId": f"i-{index:017x}",
            "ImageId": self.pin.ami_id,
            "Placement": {"AvailabilityZone": self.pin.availability_zone},
            "MetadataOptions": {"HttpEndpoint": "disabled"},
        }]}


def fixture():
    pinned = LaunchReservation(
        org_id=uuid4(), job_id=uuid4(), generation=2,
        ami_id="ami-00000000000000001", account_id="123456789012",
        availability_zone="us-east-1a",
        subnet_id="subnet-00000000000000001",
        security_group_id="sg-00000000000000001",
        kms_key_arn="arn:aws:kms:us-east-1:123456789012:key/test",
    )
    plan = _plan(
        pinned=pinned,
        image=AmiCandidate(pinned.ami_id, "snap-00000000000000001"),
        network=IsolationCandidate(
            "vpc-00000000000000001", pinned.subnet_id,
            pinned.security_group_id,
        ),
        region="us-east-1",
    )
    return pinned, plan, FakeEC2(pinned)


def wire(monkeypatch, *, fail_commit_kind=None, stale_kind=None):
    saved = []
    events = []
    state = {"db_open": False}

    @asynccontextmanager
    async def scoped(sessions, org_id):
        assert not state["db_open"]
        state["db_open"] = True
        try:
            yield object()
        finally:
            state["db_open"] = False

    async def prepare(session, *, kind, **kwargs):
        assert state["db_open"]
        saved.append(("PREPARED", kind))
        events.append(("PREPARED", kind))

    async def record(session, *, kind, resource_id, **kwargs):
        assert state["db_open"]
        if kind == fail_commit_kind:
            raise OSError("database unreachable after AWS returned")
        saved.append(("RECORDED", kind, resource_id))
        events.append(("RECORDED", kind))
        return "RECORDED_QUARANTINED" if kind == stale_kind else "RECORDED"

    async def quarantine(session, *, kind, **kwargs):
        assert state["db_open"]
        saved.append(("UNKNOWN", kind))
        events.append(("UNKNOWN", kind))

    monkeypatch.setattr(controller, "organization_session", scoped)
    monkeypatch.setattr(controller, "prepare_creation", prepare)
    monkeypatch.setattr(controller, "record_creation", record)
    monkeypatch.setattr(controller, "quarantine_creation", quarantine)
    return saved, events, state


def call(pin, plan, client, *, enabled=False):
    return asyncio.run(controller.create_guest_resources(
        sessions=object(), ec2=client, pinned=pin,
        actor_id=uuid4(), plan=plan, region="us-east-1",
        explicitly_enabled=enabled,
        clock=lambda: datetime(2026, 11, 21, tzinfo=timezone.utc),
    ))


def test_disabled_by_default_creates_nothing(monkeypatch):
    pin, plan, client = fixture()
    saved, _, _ = wire(monkeypatch)
    with pytest.raises(PermissionError):
        call(pin, plan, client)
    assert not client.calls and not saved


def test_successful_aws_creation_is_prepared_and_recorded_before_next_call(monkeypatch):
    pin, plan, client = fixture()
    saved, events, state = wire(monkeypatch)
    result = call(pin, plan, client, enabled=True)
    assert result == (
        "vol-00000000000000001",
        "vol-00000000000000002",
        "i-00000000000000003",
    )
    assert [item[0] for item in saved] == [
        "PREPARED", "RECORDED", "PREPARED",
        "RECORDED", "PREPARED", "RECORDED",
    ]
    assert [x[0] for x in client.calls] == [
        "create_volume", "create_volume", "run_instances",
    ]
    assert not state["db_open"]
    assert not any(x[0] == "UNKNOWN" for x in events)
    assert not any(x[0] in ("attach_volume", "terminate_instances") for x in client.calls)


@pytest.mark.parametrize("number", [1, 2, 3])
def test_aws_timeout_quarantines_and_never_retries_or_continues(monkeypatch, number):
    pin, plan, client = fixture()
    client.fail_number = number
    saved, _, state = wire(monkeypatch)
    with pytest.raises(controller.CreationUnknown, match="attempt quarantined"):
        call(pin, plan, client, enabled=True)
    assert len(client.calls) == number
    assert saved[-1] == ("UNKNOWN", ("INPUT_EBS", "OUTPUT_EBS", "INSTANCE")[number - 1])
    assert not state["db_open"]


@pytest.mark.parametrize("number", [1, 2, 3])
def test_bad_aws_response_is_unknown_and_not_success(monkeypatch, number):
    pin, plan, client = fixture()
    client.malformed_number = number
    saved, _, _ = wire(monkeypatch)
    with pytest.raises(controller.CreationUnknown):
        call(pin, plan, client, enabled=True)
    assert len(client.calls) == number
    assert saved[-1][0] == "UNKNOWN"


def test_stale_success_stops_before_next_cloud_call(monkeypatch):
    pin, plan, client = fixture()
    saved, _, _ = wire(monkeypatch, stale_kind="INPUT_EBS")
    with pytest.raises(controller.CreationUnknown, match="trusted lease"):
        call(pin, plan, client, enabled=True)
    assert len(client.calls) == 1
    assert saved[-1][0] == "RECORDED"


def test_db_ack_failure_is_unknown_and_never_retries(monkeypatch):
    pin, plan, client = fixture()
    saved, _, _ = wire(monkeypatch, fail_commit_kind="OUTPUT_EBS")
    with pytest.raises(controller.CreationUnknown, match="durable journal"):
        call(pin, plan, client, enabled=True)
    assert len(client.calls) == 2
    assert saved[-1][0] == "PREPARED"


def test_modified_plan_denies_before_any_aws_or_database_work(monkeypatch):
    pin, plan, client = fixture()
    saved, _, _ = wire(monkeypatch)
    plan.run_instances["IamInstanceProfile"] = {"Arn": "unauthorized"}
    with pytest.raises(ValueError, match="changed AWS"):
        call(pin, plan, client, enabled=True)
    assert not client.calls and not saved
