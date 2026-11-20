"""Native FIFO handoff: bounded metadata, stable dedup identity, fail closed."""
import asyncio
import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from aegentra.outbox_dispatch import OutboxClaim
from aegentra.outbox_worker import SinkUnavailable, SqsFifoSink


class FakeSqs:
    def __init__(self):
        self.messages = []
        self.fail = False

    def send_message(self, **kwargs):
        if self.fail:
            raise OSError("fake dependency outage")
        self.messages.append(kwargs)
        return {"MessageId": "6c2e05e7-7be2-4cd8-a520-87d011a55555"}


def example():
    org = uuid4()
    return OutboxClaim(
        org_id=org, event_id=uuid4(), stream="release",
        sequence=8, event_type="INDEPENDENT_WITNESS_REGISTERED",
        audit_hash="a" * 64, generation=3, attempt=3,
        nonce="n" * 43,
        lease_expires=datetime.now(timezone.utc),
    )


def test_sqs_fifio_enqueue_uses_immutable_id_and_safe_metadata_only():
    fake = FakeSqs()
    sink = SqsFifoSink(
        sqs=fake,
        queue_url="https://sqs.us-east-1.amazonaws.com/123456789012/events.fifo",
    )
    claim = example()
    ref = asyncio.run(sink.deliver(claim))
    assert ref.startswith("sqs:")
    assert len(fake.messages) == 1
    sent = fake.messages[0]
    assert sent["MessageDeduplicationId"] == claim.event_id.hex
    assert sent["MessageGroupId"] == f"{claim.org_id.hex}:release"
    body = json.loads(sent["MessageBody"])
    assert body == {
        "kind": "aegentra.outbox.event.v1",
        "org_id": str(claim.org_id),
        "event_id": str(claim.event_id),
        "stream": claim.stream,
        "sequence": 8,
        "event_type": "INDEPENDENT_WITNESS_REGISTERED",
        "audit_sha256": "a" * 64,
    }
    assert "nonce" not in body and "lease" not in body


@pytest.mark.parametrize("url", [
    "http://sqs.example.test/events.fifo",
    "https://sqs.example.test/events",
    "https://username:secret@sqs.example.test/events.fifo",
    "https://sqs.example.test/events.fifo?override=1",
    "",
])
def test_rejects_non_enrolled_transport_url(url):
    with pytest.raises(ValueError):
        SqsFifoSink(sqs=FakeSqs(), queue_url=url)


def test_dependency_failure_does_not_look_like_success():
    fake = FakeSqs()
    fake.fail = True
    sink = SqsFifoSink(
        sqs=fake,
        queue_url="https://sqs.us-east-1.amazonaws.com/123456789012/events.fifo",
    )
    with pytest.raises(SinkUnavailable):
        asyncio.run(sink.deliver(example()))


def test_unacknowledged_sqs_response_is_not_delivery():
    class MissingId:
        def send_message(self, **kwargs):
            return {}

    sink = SqsFifoSink(
        sqs=MissingId(),
        queue_url="https://sqs.us-east-1.amazonaws.com/123456789012/events.fifo",
    )
    with pytest.raises(SinkUnavailable):
        asyncio.run(sink.deliver(example()))
