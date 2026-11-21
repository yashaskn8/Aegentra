"""Native one-shot bridge detach verification, using only AWS read APIs.

Two time-separated AWS inventories happen outside any PostgreSQL transaction.
The bridge later rechecks immutable journal pins under a DB lock. This records
physical detachment, not isolation, AMI provenance, or release approval.

Run only under an independently provisioned read-only AWS inventory role and a
separate bridge database role. Do not run in the browser BFF or analysis guest.
"""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegentra.bridge_custody import AttemptCustody
from aegentra.bridge_journal import load_attempt_custody, record_verified_detach
from aegentra.native_detach_collector import collect_detached_inventory
from aegentra.persistence import make_engine, organization_session


async def attest_native_detach(
    *, sessions: async_sessionmaker[AsyncSession],
    ec2: Any, sts: Any, org_id: UUID, job_id: UUID,
    generation: int, actor_id: UUID,
) -> AttemptCustody:
    """Collect, separate by 31 seconds, revalidate and commit one detached state."""
    if generation < 1:
        raise ValueError("attempt generation must be positive")
    async with organization_session(sessions, org_id) as session:
        expected = await load_attempt_custody(
            session, org_id=org_id, job_id=job_id, generation=generation,
        )
    first = await asyncio.to_thread(
        collect_detached_inventory, ec2=ec2, sts=sts, expected=expected,
    )
    # No DB lock held. The second pass is an independent set of AWS reads.
    await asyncio.sleep(31)
    second = await asyncio.to_thread(
        collect_detached_inventory, ec2=ec2, sts=sts, expected=expected,
    )
    async with organization_session(sessions, org_id) as session:
        return await record_verified_detach(
            session, org_id=org_id, job_id=job_id, generation=generation,
            actor_id=actor_id, first=first, second=second,
            now=datetime.now(timezone.utc),
        )


def main() -> None:
    """One-shot native bridge command; AWS access comes from ambient IAM role."""
    import boto3
    from botocore.config import Config

    database_url = os.environ["AEGENTRA_BRIDGE_DATABASE_URL"]
    org_id = UUID(os.environ["AEGENTRA_BRIDGE_ORG_ID"])
    job_id = UUID(os.environ["AEGENTRA_BRIDGE_JOB_ID"])
    generation = int(os.environ["AEGENTRA_BRIDGE_GENERATION"])
    actor_id = UUID(os.environ["AEGENTRA_BRIDGE_ACTOR_ID"])
    region = os.environ["AEGENTRA_BRIDGE_AWS_REGION"]
    config = Config(
        connect_timeout=2, read_timeout=3,
        retries={"max_attempts": 2, "mode": "standard"},
    )
    ec2 = boto3.client("ec2", region_name=region, config=config)
    sts = boto3.client("sts", region_name=region, config=config)
    engine = make_engine(database_url)

    async def run() -> None:
        try:
            await attest_native_detach(
                sessions=async_sessionmaker(engine, expire_on_commit=False),
                ec2=ec2, sts=sts, org_id=org_id, job_id=job_id,
                generation=generation, actor_id=actor_id,
            )
        finally:
            await engine.dispose()

    asyncio.run(run())


if __name__ == "__main__":
    main()
