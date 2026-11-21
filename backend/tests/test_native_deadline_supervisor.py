"""No live AWS: simulate 30-second bounded watchdog and stop fencing."""
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from aegentra import native_deadline_supervisor as supervisor


class Clock:
    def __init__(self):
        self.at = datetime(2026, 11, 21, 0, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.at

    async def sleep(self, seconds):
        assert seconds == 30
        self.at += timedelta(seconds=seconds)


def setup(monkeypatch, states):
    events = []
    identities = [uuid4() for _ in range(3)]
    clock = Clock()
    flags = {"inside_db": False, "fail": None}

    @asynccontextmanager
    async def session(sessions, org_id):
        assert org_id == identities[0]
        assert not flags["inside_db"]
        flags["inside_db"] = True
        events.append("db-open")
        try:
            yield object()
        finally:
            flags["inside_db"] = False
            events.append("db-closed")

    async def heartbeat(session, *, org_id, job_id, generation, nonce, now):
        assert flags["inside_db"]
        assert (org_id, job_id, generation, nonce) == (
            identities[0], identities[1], 2, "n" * 43,
        )
        events.append("heartbeat")
        if flags["fail"] == "heartbeat":
            raise OSError("postgres unavailable")
        return states.pop(0)

    async def terminate(*, sessions, ec2, sts, org_id, job_id, generation,
                        actor_id, operator_stop, explicitly_enabled, clock):
        assert not flags["inside_db"]
        assert operator_stop and explicitly_enabled
        assert (org_id, job_id, actor_id) == tuple(identities)
        events.append("terminate")
        if flags["fail"] == "terminate":
            raise TimeoutError("EC2 uncertain")
        return supervisor.TERMINATION_REQUESTED

    monkeypatch.setattr(supervisor, "organization_session", session)
    monkeypatch.setattr(supervisor, "heartbeat_physical_attempt", heartbeat)
    monkeypatch.setattr(supervisor, "request_native_termination", terminate)
    return identities, events, clock, flags


def run(identities, clock, *, enabled=True, sleep=None, **extra):
    return asyncio.run(supervisor.supervise_native_attempt(
        sessions=object(), ec2=object(), sts=object(),
        org_id=identities[0], job_id=identities[1], actor_id=identities[2],
        generation=2, nonce="n" * 43, explicitly_enabled=enabled,
        clock=clock, sleep=clock.sleep if sleep is None else sleep, **extra,
    ))


def test_watchdog_disabled_by_default_has_no_side_effects(monkeypatch):
    ids, events, clock, _ = setup(monkeypatch, ["RENEWED"])
    with pytest.raises(PermissionError):
        run(ids, clock, enabled=False)
    assert events == []


def test_several_30_second_heartbeats_then_one_termination(monkeypatch):
    ids, events, clock, flags = setup(
        monkeypatch, ["RENEWED", "RENEWED", "RENEWED", "STOP_REQUIRED"],
    )
    result = run(ids, clock)
    assert result == supervisor.TERMINATION_REQUESTED
    assert events.count("heartbeat") == 4
    assert events.count("terminate") == 1
    assert events[-2:] == ["db-closed", "terminate"]
    assert clock.at == datetime(
        2026, 11, 21, 0, 1, 30, tzinfo=timezone.utc,
    )
    assert not flags["inside_db"]


def test_immediate_stop_does_not_renew_or_wait(monkeypatch):
    ids, events, clock, _ = setup(monkeypatch, ["STOP_REQUIRED"])
    assert run(ids, clock) == supervisor.TERMINATION_REQUESTED
    assert events == ["db-open", "heartbeat", "db-closed", "terminate"]


@pytest.mark.parametrize("outcome", ["RECONCILE", "unrecognized"])
def test_uncertain_or_unknown_state_never_invokes_aws(monkeypatch, outcome):
    ids, events, clock, _ = setup(monkeypatch, [outcome])
    with pytest.raises(supervisor.SupervisionUnknown):
        run(ids, clock)
    assert "terminate" not in events


@pytest.mark.parametrize("failure", ["heartbeat", "terminate"])
def test_db_or_ec2_failures_have_no_false_stop_receipt(monkeypatch, failure):
    ids, events, clock, flags = setup(monkeypatch, ["STOP_REQUIRED"])
    flags["fail"] = failure
    with pytest.raises(supervisor.SupervisionUnknown, match="reconciliation"):
        run(ids, clock)
    assert "terminate" not in events if failure == "heartbeat" else "terminate" in events


def test_fixed_tick_budget_fails_closed(monkeypatch):
    ids, events, clock, _ = setup(monkeypatch, ["RENEWED"] * 20)
    with pytest.raises(supervisor.SupervisionUnknown, match="heartbeat budget"):
        run(ids, clock)
    assert events.count("heartbeat") == 20
    assert "terminate" not in events


def test_stalled_clock_does_not_repeat_heartbeat(monkeypatch):
    ids, events, clock, _ = setup(monkeypatch, ["RENEWED", "RENEWED"])
    async def stalled(seconds):
        assert seconds == 30
    with pytest.raises(supervisor.SupervisionUnknown, match="clock"):
        run(ids, clock, sleep=stalled)
    assert events.count("heartbeat") == 1
    assert "terminate" not in events


def test_invalid_nonce_is_rejected_before_db(monkeypatch):
    ids, events, clock, _ = setup(monkeypatch, ["RENEWED"])
    with pytest.raises(ValueError):
        run(ids, clock, nonce="bad")
    assert events == []


def test_cancellation_leaves_no_false_termination_receipt(monkeypatch):
    ids, events, clock, flags = setup(monkeypatch, ["RENEWED"])
    async def cancelled(seconds):
        raise asyncio.CancelledError
    with pytest.raises(asyncio.CancelledError):
        run(ids, clock, sleep=cancelled)
    assert "terminate" not in events
    assert not flags["inside_db"]
