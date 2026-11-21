"""A read-only native launch preflight never invokes AWS mutations."""
import asyncio
from contextlib import asynccontextmanager
from dataclasses import replace
from uuid import uuid4

import pytest

from aegentra import native_launch_preflight as runner
from aegentra.bridge_journal import LaunchReservation
from aegentra.native_ami_preflight import AmiCandidate, AmiPin, AmiRejected
from aegentra.native_isolation_guard import GuestNetworkPin, IsolationCandidate, IsolationRejected


def fixture():
    pin = LaunchReservation(
        org_id=uuid4(), job_id=uuid4(), generation=2,
        ami_id="ami-00000000000000001", account_id="123456789012",
        availability_zone="us-east-1a",
        subnet_id="subnet-00000000000000001",
        security_group_id="sg-00000000000000001",
        kms_key_arn="arn:aws:kms:us-east-1:123456789012:key/verified",
    )
    image = AmiPin(
        analysis_account_id=pin.account_id, ami_id=pin.ami_id,
        image_owner_id=pin.account_id,
        root_snapshot_id="snap-00000000000000001",
        snapshot_owner_id=pin.account_id,
        kms_key_arn=pin.kms_key_arn, region="us-east-1",
    )
    network = GuestNetworkPin(
        account_id=pin.account_id, vpc_id="vpc-00000000000000001",
        subnet_id=pin.subnet_id, security_group_id=pin.security_group_id,
        availability_zone=pin.availability_zone,
    )
    return pin, image, network


def install(monkeypatch, *, fail=None):
    pin, image, network = fixture()
    state = {"db": False, "queries": 0, "images": 0, "networks": 0}

    @asynccontextmanager
    async def scoped(sessions, org_id):
        assert org_id == pin.org_id
        assert not state["db"]
        state["db"] = True
        try:
            yield object()
        finally:
            state["db"] = False

    async def load(session, *, org_id, job_id, generation, now):
        assert state["db"]
        assert (org_id, job_id, generation) == (pin.org_id, pin.job_id, pin.generation)
        state["queries"] += 1
        if fail == "changed" and state["queries"] == 2:
            return replace(pin, ami_id="ami-00000000000000002")
        return pin

    def ami(*, ec2, sts, pin):
        assert not state["db"]
        state["images"] += 1
        if fail == "image":
            raise AmiRejected("unqualified")
        return AmiCandidate(pin.ami_id, pin.root_snapshot_id)

    def topology(*, ec2, resolver, sts, pinned, now):
        assert not state["db"]
        state["networks"] += 1
        if fail == "network":
            raise IsolationRejected("unqualified")
        return IsolationCandidate(pinned.vpc_id, pinned.subnet_id, pinned.security_group_id)

    monkeypatch.setattr(runner, "organization_session", scoped)
    monkeypatch.setattr(runner, "load_reserved_launch", load)
    monkeypatch.setattr(runner, "verify_native_ami", ami)
    monkeypatch.setattr(runner, "evaluate_native_guest_network", topology)
    return pin, image, network, state


def evaluate(pin, image, network):
    return asyncio.run(runner.preflight_native_launch(
        sessions=object(), ec2=object(), sts=object(), resolver=object(),
        org_id=pin.org_id, job_id=pin.job_id, generation=pin.generation,
        image_pin=image, network_pin=network,
    ))


def test_read_only_preflight_produces_bounded_plan_after_fresh_db_recheck(monkeypatch):
    pin, image, network, state = install(monkeypatch)
    result = evaluate(pin, image, network)
    assert result.status == "SHADOW_ONLY_EXTERNAL_QUALIFICATION_REQUIRED"
    assert state == {"db": False, "queries": 2, "images": 1, "networks": 1}
    req = result.run_instances
    assert req["ImageId"] == pin.ami_id
    assert req["MinCount"] == req["MaxCount"] == 1
    assert req["InstanceType"] == "t3.small"
    assert req["MetadataOptions"]["HttpEndpoint"] == "disabled"
    assert req["MetadataOptions"]["InstanceMetadataTags"] == "disabled"
    assert req["NetworkInterfaces"][0]["AssociatePublicIpAddress"] is False
    assert req["NetworkInterfaces"][0]["Ipv6AddressCount"] == 0
    assert not {"IamInstanceProfile", "KeyName", "UserData", "LaunchTemplate"} & set(req)
    assert len(result.create_volumes) == 2
    for volume in result.create_volumes:
        assert volume["Encrypted"] is True
        assert volume["KmsKeyId"] == pin.kms_key_arn
        assert volume["Size"] == 1
    tokens = [req["ClientToken"]] + [v["ClientToken"] for v in result.create_volumes]
    assert len(set(tokens)) == 3
    assert all(len(t) == 64 for t in tokens)
    assert len(result.sha256()) == 64


@pytest.mark.parametrize("tamper", ["ami", "account", "subnet", "az", "kms"])
def test_mismatched_enrollment_never_queries_aws(monkeypatch, tamper):
    pin, image, network, state = install(monkeypatch)
    if tamper == "ami":
        image = replace(image, ami_id="ami-00000000000000002")
    elif tamper == "account":
        network = replace(network, account_id="000000000000")
    elif tamper == "subnet":
        network = replace(network, subnet_id="subnet-00000000000000002")
    elif tamper == "az":
        network = replace(network, availability_zone="us-east-1b")
    else:
        image = replace(image, kms_key_arn="arn:aws:kms:us-east-1:123456789012:key/unpinned")
    with pytest.raises(runner.LaunchPreflightRejected):
        evaluate(pin, image, network)
    assert state == {"db": False, "queries": 1, "images": 0, "networks": 0}


@pytest.mark.parametrize("fail,error_type", [
    ("image", AmiRejected), ("network", IsolationRejected),
    ("changed", runner.LaunchPreflightRejected),
])
def test_incomplete_checks_never_return_launch_plan(monkeypatch, fail, error_type):
    pin, image, network, state = install(monkeypatch, fail=fail)
    with pytest.raises(error_type):
        evaluate(pin, image, network)
    assert not state["db"]


def test_changed_plan_inputs_are_rejected(monkeypatch):
    pin, image, network, state = install(monkeypatch)
    pin = replace(pin, subnet_id="subnet-unregistered")
    # A fabricated DB pin cannot satisfy the exact external network identity.
    with pytest.raises(runner.LaunchPreflightRejected):
        evaluate(pin, image, network)
    assert state["queries"] == 1
