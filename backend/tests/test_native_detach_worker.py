"""Two native AWS inventory passes occur outside DB transactions."""
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from aegentra.bridge_custody import AttemptCustody, CustodyError, DetachedInventory
from aegentra import native_detach_worker as worker


def fixture():
    return AttemptCustody(
        job_id=uuid4(), generation=1, account_id="123456789012",
        availability_zone="us-east-1a", instance_id="i-00000000000000001",
        ami_id="ami-00000000000000001",
        subnet_id="subnet-pinned", security_group_id="sg-pinned",
        input_volume_id="vol-00000000000000001",
        output_volume_id="vol-00000000000000002",
        kms_key_arn="arn:aws:kms:us-east-1:123456789012:key/test",
    )


def install(monkeypatch, *, fail_second=False):
    expected = fixture()
    org, actor = uuid4(), uuid4()
    state = {"inside_db": False, "calls": 0, "recorded": 0, "slept": False}

    @asynccontextmanager
    async def org_session(sessions, org_id):
        assert org_id == org
        assert not state["inside_db"]
        state["inside_db"] = True
        try:
            yield object()
        finally:
            state["inside_db"] = False

    async def load(session, *, org_id, job_id, generation):
        assert state["inside_db"]
        assert (org_id, job_id, generation) == (org, expected.job_id, 1)
        return expected

    baseline = datetime.now(timezone.utc) - timedelta(minutes=1)

    def collect(*, ec2, sts, expected: AttemptCustody):
        assert not state["inside_db"]
        state["calls"] += 1
        if fail_second and state["calls"] == 2:
            raise CustodyError("second AWS inventory unavailable")
        return DetachedInventory(
            expected.account_id,
            baseline + timedelta(seconds=31 * (state["calls"] - 1)),
            (), (),
        )

    async def sleep(seconds):
        assert not state["inside_db"]
        assert seconds >= 30
        state["slept"] = True

    async def record(session, *, org_id, job_id, generation, actor_id,
                     first, second, now):
        assert state["inside_db"]
        assert (org_id, job_id, generation, actor_id) == (
            org, expected.job_id, 1, actor,
        )
        assert first.observed_at < second.observed_at
        assert now.tzinfo is not None
        state["recorded"] += 1
        return expected

    monkeypatch.setattr(worker, "organization_session", org_session)
    monkeypatch.setattr(worker, "load_attempt_custody", load)
    monkeypatch.setattr(worker, "collect_detached_inventory", collect)
    monkeypatch.setattr(worker.asyncio, "sleep", sleep)
    monkeypatch.setattr(worker, "record_verified_detach", record)
    return expected, org, actor, state


def test_native_detach_is_read_only_outside_transactions(monkeypatch):
    expected, org, actor, state = install(monkeypatch)
    result = asyncio.run(worker.attest_native_detach(
        sessions=object(), ec2=object(), sts=object(), org_id=org,
        job_id=expected.job_id, generation=1, actor_id=actor,
    ))
    assert result == expected
    assert state == {"inside_db": False, "calls": 2, "recorded": 1, "slept": True}


def test_second_aws_inventory_failure_does_not_commit_detachment(monkeypatch):
    expected, org, actor, state = install(monkeypatch, fail_second=True)
    with pytest.raises(CustodyError):
        asyncio.run(worker.attest_native_detach(
            sessions=object(), ec2=object(), sts=object(), org_id=org,
            job_id=expected.job_id, generation=1, actor_id=actor,
        ))
    assert state["calls"] == 2
    assert state["recorded"] == 0
    assert not state["inside_db"]


def test_invalid_generation_never_opens_db(monkeypatch):
    expected, org, actor, state = install(monkeypatch)
    with pytest.raises(ValueError):
        asyncio.run(worker.attest_native_detach(
            sessions=object(), ec2=object(), sts=object(), org_id=org,
            job_id=expected.job_id, generation=0, actor_id=actor,
        ))
    assert state["calls"] == state["recorded"] == 0
