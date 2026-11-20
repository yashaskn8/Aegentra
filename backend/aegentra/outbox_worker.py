"""Native SQS FIFO delivery adapter for transactionally leased outbox events.

No network call is made while PostgreSQL locks are held. The SQS response
confirms queue acceptance, not final downstream consumer processing.
Consumers MUST deduplicate by immutable event UUID indefinitely.
"""
from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Protocol
from urllib.parse import urlsplit
from uuid import UUID

import rfc8785
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegentra.outbox_dispatch import (
    OutboxClaim, acknowledge_delivery, claim_outbox, fail_delivery,
)
from aegentra.persistence import make_engine, organization_session


class SinkUnavailable(ValueError):
    pass


class DeliverySink(Protocol):
    async def deliver(self, claim: OutboxClaim) -> str: ...


@dataclass(frozen=True)
class DispatchSummary:
    claimed: int
    enqueued: int
    retried: int
    stale: int


class SqsFifoSink:
    def __init__(self, *, sqs: Any, queue_url: str):
        parsed = urlsplit(queue_url)
        if (
            parsed.scheme != "https" or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or not parsed.path.endswith(".fifo")
            or parsed.query or parsed.fragment or len(queue_url) > 512
        ):
            raise ValueError("only a fixed, configured HTTPS FIFO queue is supported")
        self.sqs, self.queue_url = sqs, queue_url

    async def deliver(self, claim: OutboxClaim) -> str:
        payload = rfc8785.dumps({
            "kind": "aegentra.outbox.event.v1",
            "org_id": str(claim.org_id),
            "event_id": str(claim.event_id),
            "stream": claim.stream,
            "sequence": claim.sequence,
            "event_type": claim.event_type,
            "audit_sha256": claim.audit_hash,
        })
        if len(payload) > 4096:
            raise SinkUnavailable("outbox metadata exceeds transport budget")
        try:
            response = await asyncio.to_thread(
                self.sqs.send_message,
                QueueUrl=self.queue_url,
                MessageBody=payload.decode("utf-8"),
                MessageGroupId=f"{claim.org_id.hex}:{claim.stream}",
                MessageDeduplicationId=claim.event_id.hex,
            )
        except Exception as exc:
            raise SinkUnavailable("independent queue delivery unavailable") from exc
        message_id = response.get("MessageId")
        if (
            not isinstance(message_id, str)
            or not re.fullmatch(r"[A-Za-z0-9-]{8,120}", message_id)
        ):
            raise SinkUnavailable("no trusted SQS queue acceptance reference")
        return "sqs:" + message_id


async def deliver_batch(
    *, sessions: async_sessionmaker[AsyncSession], org_id: UUID,
    sink: DeliverySink, now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> DispatchSummary:
    """Claim/commit, send, then separately commit an ACK or retry."""
    async with organization_session(sessions, org_id) as session:
        claims = await claim_outbox(
            session, org_id=org_id, now=now(),
        )
    enqueued = retried = stale = 0
    for claim in claims:
        try:
            ref = await sink.deliver(claim)
        except SinkUnavailable:
            async with organization_session(sessions, org_id) as session:
                status = await fail_delivery(
                    session, org_id=org_id, event_id=claim.event_id,
                    generation=claim.generation, nonce=claim.nonce,
                    code="DEPENDENCY_UNAVAILABLE", now=now(),
                )
            if status == "STALE":
                stale += 1
            else:
                retried += 1
            continue
        async with organization_session(sessions, org_id) as session:
            accepted = await acknowledge_delivery(
                session, org_id=org_id, event_id=claim.event_id,
                generation=claim.generation, nonce=claim.nonce,
                delivery_reference=ref, now=now(),
            )
        if accepted:
            enqueued += 1
        else:
            stale += 1
    return DispatchSummary(len(claims), enqueued, retried, stale)


def main() -> None:
    """One-shot native systemd-timer entrypoint; no Docker or daemon framework."""
    import boto3
    from botocore.config import Config

    database_url = os.environ["AEGENTRA_OUTBOX_DATABASE_URL"]
    org_id = UUID(os.environ["AEGENTRA_OUTBOX_ORG_ID"])
    queue_url = os.environ["AEGENTRA_OUTBOX_FIFO_QUEUE_URL"]
    region = os.environ["AEGENTRA_OUTBOX_AWS_REGION"]
    client = boto3.client(
        "sqs", region_name=region,
        config=Config(
            connect_timeout=2, read_timeout=3,
            retries={"max_attempts": 2, "mode": "standard"},
        ),
    )
    sink = SqsFifoSink(sqs=client, queue_url=queue_url)
    engine = make_engine(database_url)
    async def execute() -> None:
        try:
            await deliver_batch(
                sessions=async_sessionmaker(engine, expire_on_commit=False),
                org_id=org_id, sink=sink,
            )
        finally:
            await engine.dispose()
    asyncio.run(execute())


if __name__ == "__main__":
    main()
