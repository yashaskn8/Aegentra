"""Shadow-only serialized release-intent ledger.

No API endpoints, public publication action, or ENFORCED transitions are
exposed here. A selection is never a published revision. Only separately
qualified authorities may later witness and publish.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegentra.audit import record_event
from aegentra.db import (
    ReleaseEndorsement, ReleaseGrant, ReleaseOrgGuard,
    ReleaseSelection, ReleaseTarget,
)
from aegentra.review_crypto import (
    ReviewSubject, ReviewerCredential, SignedEndorsement, verify_approval_set,
)
from aegentra.staging_proof import StagingProof, verify_staging_proof


class ReleaseConflict(ValueError):
    pass


def trusted_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class ShadowGrant:
    nonce: str
    subject_sha256: str
    approval_set_sha256: str
    expires_at: datetime


@asynccontextmanager
async def release_session(
    sessions: async_sessionmaker[AsyncSession], org_id: UUID
) -> AsyncIterator[AsyncSession]:
    """Primary-writer SERIALIZABLE transaction with transaction-local RLS."""
    if not isinstance(org_id, UUID):
        raise TypeError("trusted organization UUID required")
    async with sessions() as session:
        async with session.begin():
            await session.execute(text("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"))
            await session.execute(text("SET LOCAL lock_timeout = '1500ms'"))
            await session.execute(text("SET LOCAL statement_timeout = '5000ms'"))
            await session.execute(
                text("SELECT set_config('aegentra.org_id', :org, true)"),
                {"org": str(org_id)},
            )
            yield session


async def _locked(
    session: AsyncSession, org_id: UUID, target_id: UUID
) -> tuple[ReleaseOrgGuard, ReleaseTarget]:
    # This lock order is fixed across all release mutations.
    root = await session.scalar(
        select(ReleaseOrgGuard).where(ReleaseOrgGuard.org_id == org_id).with_for_update()
    )
    if root is None:
        raise ReleaseConflict("installation is not enrolled")
    target = await session.scalar(
        select(ReleaseTarget).where(
            ReleaseTarget.org_id == org_id, ReleaseTarget.id == target_id
        ).with_for_update()
    )
    if target is None:
        raise ReleaseConflict("release target unavailable")
    return root, target


async def enroll_shadow_target(
    session: AsyncSession, *,
    org_id: UUID, target_id: UUID, asset_id: UUID,
    destination_host: str, actor_id: UUID,
) -> None:
    if not destination_host or destination_host != destination_host.lower():
        raise ReleaseConflict("destination host must be normalized")
    root = await session.scalar(
        select(ReleaseOrgGuard).where(ReleaseOrgGuard.org_id == org_id).with_for_update()
    )
    if root is None:
        raise ReleaseConflict("offline installation root is missing")
    if await session.scalar(
        select(ReleaseTarget.id).where(
            ReleaseTarget.org_id == org_id, ReleaseTarget.id == target_id
        )
    ):
        raise ReleaseConflict("target already exists")
    session.add(ReleaseTarget(
        org_id=org_id, id=target_id, asset_id=asset_id,
        destination_host=destination_host, mode="SHADOW", guard="ACTIVE",
        epoch=1, next_attempt_sequence=0, published_revision=0,
    ))
    await session.flush()
    await record_event(
        session, org_id=org_id, actor_id=actor_id, stream="release",
        event_type="RELEASE_TARGET_ENROLLED_SHADOW",
        body={"target_id": str(target_id), "asset_id": str(asset_id)},
    )


async def issue_shadow_grant(
    session: AsyncSession, *,
    subject: ReviewSubject,
    endorsements: tuple[SignedEndorsement, SignedEndorsement],
    enrolled: dict[str, ReviewerCredential],
    actor_id: UUID,
    clock: Callable[[], datetime] = trusted_now,
) -> ShadowGrant:
    """Persist independently checked signatures and single-use challenges.

    This issues a short-lived test grant ONLY while target.mode == SHADOW.
    It is not a protected GRANT and cannot be used for production publication.
    """
    checks_at = clock()
    checks = verify_approval_set(
        subject=subject, endorsements=endorsements, enrolled=enrolled,
        used_challenges=frozenset(), now=checks_at,
    )
    root, target = await _locked(session, subject.org_id, subject.target_id)
    now = clock()  # Re-evaluate trusted wall time after taking both locks.
    if now.tzinfo is None:
        raise ReleaseConflict("untrusted authority clock")
    if (
        root.incarnation != subject.incarnation
        or root.epoch != subject.org_epoch
        or target.epoch != subject.target_epoch
        or target.asset_id != subject.asset_id
        or target.destination_host != subject.destination_host
        or target.mode != "SHADOW"
        or target.guard != "ACTIVE"
        or target.published_revision != subject.prior_published_revision
    ):
        raise ReleaseConflict("review subject is stale or target is not in safe shadow")
    # Reviewer validity may have changed while locks were being acquired.
    checks = verify_approval_set(
        subject=subject, endorsements=endorsements, enrolled=enrolled,
        used_challenges=frozenset(), now=now,
    )
    first_expiry = min(item.body.expires_at for item in endorsements)
    expires_at = min(now + timedelta(seconds=60), first_expiry)
    if expires_at <= now + timedelta(seconds=3):
        raise ReleaseConflict("review validity too close to expiry")
    nonce = secrets.token_urlsafe(32)
    for item in endorsements:
        body = item.body
        session.add(ReleaseEndorsement(
            org_id=subject.org_id,
            challenge_sha256=hashlib.sha256(body.challenge_nonce.encode("ascii")).digest(),
            subject_sha256=bytes.fromhex(subject.digest()),
            target_id=subject.target_id, person_id=body.person_id,
            key_id=body.key_id, custody_group=body.custody_group,
            enrollment_generation=body.enrollment_generation,
            signed_body=body.model_dump(mode="json"),
            signature=item.signature, recorded_at=now,
        ))
    session.add(ReleaseGrant(
        org_id=subject.org_id, target_id=subject.target_id,
        nonce_hash=hashlib.sha256(nonce.encode("ascii")).digest(),
        subject_sha256=bytes.fromhex(subject.digest()),
        subject_body=subject.model_dump(mode="json"),
        approval_set_sha256=bytes.fromhex(checks.approval_set_sha256),
        incarnation=subject.incarnation, org_epoch=root.epoch,
        target_epoch=target.epoch,
        expected_prior_revision=target.published_revision,
        status="GRANTED", issued_at=now, expires_at=expires_at,
    ))
    await session.flush()
    await record_event(
        session, org_id=subject.org_id, actor_id=actor_id, stream="release",
        event_type="SHADOW_REVIEW_GRANTED",
        body={"target_id": str(subject.target_id), "subject_sha256": subject.digest()},
    )
    return ShadowGrant(
        nonce=nonce, subject_sha256=subject.digest(),
        approval_set_sha256=checks.approval_set_sha256,
        expires_at=expires_at,
    )


async def redeem_shadow_grant(
    session: AsyncSession, *,
    subject: ReviewSubject, nonce: str, proof: StagingProof,
    proof_signature: bytes, verifier_public_key: bytes,
    verifier_key_id: str, actor_id: UUID,
    clock: Callable[[], datetime] = trusted_now,
) -> tuple[int, str]:
    """Consume one grant and allocate a NEVER-REUSED private attempt sequence."""
    proof_hash = verify_staging_proof(
        proof=proof, signature=proof_signature,
        public_key=verifier_public_key, expected_key_id=verifier_key_id,
        subject=subject, now=clock(),
    )
    root, target = await _locked(session, subject.org_id, subject.target_id)
    now = clock()
    nonce_hash = hashlib.sha256(nonce.encode("ascii")).digest()
    grant = await session.scalar(
        select(ReleaseGrant).where(
            ReleaseGrant.org_id == subject.org_id,
            ReleaseGrant.target_id == subject.target_id,
            ReleaseGrant.nonce_hash == nonce_hash,
        ).with_for_update()
    )
    if (
        grant is None
        or root.incarnation != grant.incarnation
        or root.epoch != grant.org_epoch
        or target.epoch != grant.target_epoch
        or target.mode != "SHADOW"
        or target.guard != "ACTIVE"
        or target.published_revision != grant.expected_prior_revision
        or not hmac.compare_digest(grant.subject_sha256, bytes.fromhex(subject.digest()))
        or grant.subject_body != subject.model_dump(mode="json")
    ):
        raise ReleaseConflict("grant not currently authorized")
    if grant.status == "REDEEMED":
        selection = await session.scalar(
            select(ReleaseSelection).where(
                ReleaseSelection.org_id == subject.org_id,
                ReleaseSelection.target_id == subject.target_id,
                ReleaseSelection.attempt_sequence == grant.selection_sequence,
            )
        )
        if selection is None or selection.staging_sha256.hex() != proof_hash:
            raise ReleaseConflict("grant replay has different staging evidence")
        return selection.attempt_sequence, selection.state
    if grant.status != "GRANTED" or now + timedelta(seconds=3) >= grant.expires_at:
        raise ReleaseConflict("grant expired or consumed")
    # Require both persisted endorsement records, not only an old grant hash.
    reviewers = list((await session.scalars(
        select(ReleaseEndorsement).where(
            ReleaseEndorsement.org_id == subject.org_id,
            ReleaseEndorsement.target_id == subject.target_id,
            ReleaseEndorsement.subject_sha256 == bytes.fromhex(subject.digest()),
        )
    )).all())
    if len(reviewers) != 2 or any(
        datetime.fromisoformat(item.signed_body["expires_at"]).astimezone(timezone.utc)
        <= now.astimezone(timezone.utc)
        for item in reviewers
    ):
        raise ReleaseConflict("reviewer evidence missing or expired")

    target.next_attempt_sequence += 1
    sequence = target.next_attempt_sequence
    expires_at = min(
        now + timedelta(seconds=60),
        *(datetime.fromisoformat(item.signed_body["expires_at"]) for item in reviewers),
    )
    if expires_at <= now + timedelta(seconds=3):
        raise ReleaseConflict("selection cannot outlive approvals")
    session.add(ReleaseSelection(
        org_id=subject.org_id, target_id=subject.target_id,
        attempt_sequence=sequence, grant_nonce_hash=nonce_hash,
        subject_sha256=bytes.fromhex(subject.digest()),
        staging_sha256=bytes.fromhex(proof_hash),
        prior_published_revision=grant.expected_prior_revision,
        state="SELECTED_UNWITNESSED", created_at=now, expires_at=expires_at,
    ))
    grant.status, grant.selection_sequence = "REDEEMED", sequence
    await session.flush()
    await record_event(
        session, org_id=subject.org_id, actor_id=actor_id, stream="release",
        event_type="SHADOW_SELECTION_UNWITNESSED",
        body={"target_id": str(subject.target_id), "attempt_sequence": sequence},
    )
    return sequence, "SELECTED_UNWITNESSED"


async def set_target_guard(
    session: AsyncSession, *,
    org_id: UUID, target_id: UUID, actor_id: UUID,
    new_guard: str,
) -> int:
    """HOLD or STOP; no emergency reopen operation is supplied."""
    if new_guard not in {"HOLD_PROMOTION", "STOP_SERVING"}:
        raise ReleaseConflict("guard may only move toward restriction")
    root, target = await _locked(session, org_id, target_id)
    if target.guard == "STOP_SERVING" and new_guard != "STOP_SERVING":
        raise ReleaseConflict("STOP cannot be downgraded without governed recovery")
    if new_guard == target.guard:
        return target.epoch
    target.guard = new_guard
    target.epoch += 1
    # Epoch mismatch invalidates every outstanding grant without reusing nonce.
    await session.execute(
        update(ReleaseGrant)
        .where(
            ReleaseGrant.org_id == org_id,
            ReleaseGrant.target_id == target_id,
            ReleaseGrant.status == "GRANTED",
        ).values(status="CANCELED")
    )
    await record_event(
        session, org_id=org_id, actor_id=actor_id, stream="release",
        event_type="RELEASE_TARGET_" + new_guard,
        body={"target_id": str(target_id), "target_epoch": target.epoch},
    )
    return target.epoch
