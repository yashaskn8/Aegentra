"""Native AWS operations are simulated; no live EC2 is contacted."""
import asyncio
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from aegentra import native_physical_controller as ctl
from aegentra.bridge_custody import AttemptCustody, CustodyError
from aegentra.native_attachment_inventory import LiveInventory


NOW = datetime(2026, 11, 21, tzinfo=timezone.utc)


def fixture():
    return AttemptCustody(
        job_id=uuid4(), generation=2, account_id="123456789012",
        availability_zone="us-east-1a", instance_id="i-00000000000000001",
        ami_id="ami-00000000000000001",
        subnet_id="subnet-00000000000000001",
        security_group_id="sg-00000000000000001",
        input_volume_id="vol-00000000000000001",
        output_volume_id="vol-00000000000000002",
        kms_key_arn="arn:aws:kms:us-east-1:123456789012:key/test",
    )


class SimulatedEC2:
    def __init__(self, expected):
        self.expected = expected
        self.calls = []
        self.attached = 0
        self.fail_at = 0
        self.bad_response = 0

    def attach_volume(self, **args):
        self.calls.append(("attach", args))
        n = len(self.calls)
        if self.fail_at == n:
            raise TimeoutError("ambiguous attach")
        if self.bad_response == n:
            return {"VolumeId": "vol-untrusted"}
        self.attached = n
        return {
            "InstanceId": args["InstanceId"], "VolumeId": args["VolumeId"],
            "Device": args["Device"], "State": "attaching",
        }

    def terminate_instances(self, **args):
        self.calls.append(("terminate", args))
        if self.fail_at == 1:
            raise TimeoutError("ambiguous terminate")
        if self.bad_response == 1:
            return {"TerminatingInstances": []}
        return {"TerminatingInstances": [{
            "InstanceId": args["InstanceIds"][0],
            "CurrentState": {"Name": "shutting-down"},
        }]}


def wire(monkeypatch, *, due=False, failed_record=None, mismatch=False):
    expected = fixture()
    state = {"inside": False, "stage": [], "snapshots": [], "due": due}

    @asynccontextmanager
    async def scoped(sessions, org):
        assert not state["inside"]
        state["inside"] = True
        try:
            yield object()
        finally:
            state["inside"] = False

    async def load(session, *, org_id, job_id, generation, now):
        assert state["inside"]
        return expected, state["due"]

    def collect(*, ec2, sts, expected):
        assert not state["inside"]
        state["snapshots"].append(ec2.attached)
        return LiveInventory(expected.account_id, datetime.now(timezone.utc), {}, ({}, {}))

    def verify_count(*, expected, observed, attached):
        assert observed.account_id == expected.account_id
        assert observed in [
            x for x in [observed]
        ]
        if state["snapshots"][-1] != attached:
            raise CustodyError("physical AWS readback not at requested stage")

    def verify_term(*, expected, observed):
        assert expected.instance_id

    async def prepare(session, *, kind, **kwargs):
        assert state["inside"]
        state["stage"].append(("PREPARED", kind))
        return replace(expected, instance_id="i-00000000000000002") if mismatch else expected

    async def record(session, *, kind, **kwargs):
        assert state["inside"]
        state["stage"].append(("RECORDED", kind))
        if failed_record == kind:
            raise OSError("PostgreSQL lost after AWS operation")
        return "REQUESTED" if kind == "TERMINATE" else "VERIFIED"

    async def unknown(session, *, kind, **kwargs):
        assert state["inside"]
        state["stage"].append(("UNKNOWN", kind))

    monkeypatch.setattr(ctl, "organization_session", scoped)
    monkeypatch.setattr(ctl, "load_operation_state", load)
    monkeypatch.setattr(ctl, "collect_live_inventory", collect)
    monkeypatch.setattr(ctl, "verify_attachment_count", verify_count)
    monkeypatch.setattr(ctl, "verify_termination_inventory", verify_term)
    monkeypatch.setattr(ctl, "prepare_operation", prepare)
    monkeypatch.setattr(ctl, "record_operation", record)
    monkeypatch.setattr(ctl, "mark_operation_unknown", unknown)
    return expected, state, SimulatedEC2(expected)


def attach(expected, client, *, enabled=True):
    return asyncio.run(ctl.attach_raw_volumes(
        sessions=object(), ec2=client, sts=object(),
        org_id=uuid4(), job_id=expected.job_id, generation=expected.generation,
        actor_id=uuid4(), explicitly_enabled=enabled, clock=lambda: NOW,
    ))


def terminate(expected, client, *, enabled=True, operator_stop=False):
    return asyncio.run(ctl.request_native_termination(
        sessions=object(), ec2=client, sts=object(),
        org_id=uuid4(), job_id=expected.job_id, generation=expected.generation,
        actor_id=uuid4(), explicitly_enabled=enabled,
        operator_stop=operator_stop, clock=lambda: NOW,
    ))


def test_live_operations_disabled_by_default(monkeypatch):
    expected, state, client = wire(monkeypatch)
    with pytest.raises(PermissionError):
        attach(expected, client, enabled=False)
    with pytest.raises(PermissionError):
        terminate(expected, client, enabled=False)
    assert not client.calls and not state["stage"]


def test_two_attaches_are_prepared_and_verified_before_next(monkeypatch):
    expected, state, client = wire(monkeypatch)
    assert attach(expected, client) == "BOTH_RAW_DEVICES_VERIFIED_NOT_GUEST_EXECUTION_AUTHORITY"
    assert state["stage"] == [
        ("PREPARED", "ATTACH_INPUT"), ("RECORDED", "ATTACH_INPUT"),
        ("PREPARED", "ATTACH_OUTPUT"), ("RECORDED", "ATTACH_OUTPUT"),
    ]
    assert [c[0] for c in client.calls] == ["attach", "attach"]
    assert [c[1]["Device"] for c in client.calls] == ["/dev/sdf", "/dev/sdg"]
    assert state["snapshots"] == [0, 1, 1, 2]
    assert not state["inside"]


@pytest.mark.parametrize("stage", [1, 2])
@pytest.mark.parametrize("failure", ["timeout", "malformed"])
def test_ambiguous_attach_quarantines_once(monkeypatch, stage, failure):
    expected, state, client = wire(monkeypatch)
    if failure == "timeout":
        client.fail_at = stage
    else:
        client.bad_response = stage
    with pytest.raises(ctl.PhysicalUnknown, match="quarantined"):
        attach(expected, client)
    assert len(client.calls) == stage
    assert state["stage"][-1] == (
        "UNKNOWN", ("ATTACH_INPUT", "ATTACH_OUTPUT")[stage - 1],
    )


def test_attach_db_ack_failure_is_unknown_without_retry(monkeypatch):
    expected, state, client = wire(monkeypatch, failed_record="ATTACH_INPUT")
    with pytest.raises(ctl.PhysicalUnknown, match="durable"):
        attach(expected, client)
    assert len(client.calls) == 1
    assert state["stage"][-1] == ("RECORDED", "ATTACH_INPUT")


def test_attachment_is_rejected_if_identity_changes_after_prepare(monkeypatch):
    expected, state, client = wire(monkeypatch, mismatch=True)
    with pytest.raises(ctl.PhysicalUnknown):
        attach(expected, client)
    assert not client.calls
    assert state["stage"][-1] == ("UNKNOWN", "ATTACH_INPUT")


def test_termination_requires_due_or_explicit_operator_stop(monkeypatch):
    expected, state, client = wire(monkeypatch, due=False)
    with pytest.raises(PermissionError, match="deadline"):
        terminate(expected, client)
    assert not state["stage"] and not client.calls
    assert terminate(expected, client, operator_stop=True) == (
        "TERMINATION_REQUESTED_PENDING_INDEPENDENT_DETACH"
    )
    assert state["stage"] == [
        ("PREPARED", "TERMINATE"), ("RECORDED", "TERMINATE"),
    ]
    assert client.calls[0] == ("terminate", {"InstanceIds": [expected.instance_id]})


def test_expired_lease_termination_request_does_not_claim_detach(monkeypatch):
    expected, state, client = wire(monkeypatch, due=True)
    assert terminate(expected, client) == "TERMINATION_REQUESTED_PENDING_INDEPENDENT_DETACH"
    assert state["snapshots"] == [0]


@pytest.mark.parametrize("failure", ["timeout", "malformed"])
def test_termination_uncertainty_is_terminal(monkeypatch, failure):
    expected, state, client = wire(monkeypatch, due=True)
    if failure == "timeout":
        client.fail_at = 1
    else:
        client.bad_response = 1
    with pytest.raises(ctl.PhysicalUnknown, match="quarantined"):
        terminate(expected, client)
    assert state["stage"] == [
        ("PREPARED", "TERMINATE"), ("UNKNOWN", "TERMINATE"),
    ]
    assert len(client.calls) == 1
