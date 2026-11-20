"""Register a version-pinned independent witness for one committed selection.

No AWS call is made under a database lock. The caller must fetch exact S3
VersionId bytes and an independent nonce-bound veto snapshot out-of-band.
This stage never publishes and never enables ENFORCED.
"""
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegentra.audit import record_event
from aegentra.db import (
    ReleaseGrant, ReleasePublication, ReleaseSelection, ReleaseTarget,
)
from aegentra.gateway_signatures import (
    SignedVeto, verify_veto,
)
from aegentra.release_state import ReleaseConflict, _locked
from aegentra.review_crypto import ReviewSubject
from aegentra.witness_crypto import (
    WitnessArchiveRef, WitnessBody, WitnessSelection,
    WitnessRejected, signed_certificate_bytes, verify_witness_certificate,
)


async def witness_committed_selection(
    session: AsyncSession, *,
    org_id: UUID, target_id: UUID, attempt_sequence: int,
    actor_id: UUID, cert_body: WitnessBody, cert_signature: bytes,
    pinned_witness_key_der: bytes, archive_ref: WitnessArchiveRef,
    exact_archive_bytes: bytes, pinned_archive_bucket: str,
    live_veto: SignedVeto, veto_nonce: str, pinned_veto_key_der: bytes,
    now: datetime,
) -> str:
    """Persist WITNESSED only if current guarded DB and signed proofs agree."""
    root, target = await _locked(session, org_id, target_id)
    if (
        target.guard != "ACTIVE" or target.mode == "RETIRED"
        or target.published_revision != cert_body.prior_published_revision
    ):
        raise ReleaseConflict("target not eligible for witness")
    selection = await session.scalar(
        select(ReleaseSelection).where(
            ReleaseSelection.org_id == org_id,
            ReleaseSelection.target_id == target_id,
            ReleaseSelection.attempt_sequence == attempt_sequence,
        ).with_for_update()
    )
    if selection is None:
        raise ReleaseConflict("committed selection missing")
    grant = await session.scalar(
        select(ReleaseGrant).where(
            ReleaseGrant.org_id == org_id,
            ReleaseGrant.target_id == target_id,
            ReleaseGrant.nonce_hash == selection.grant_nonce_hash,
        ).with_for_update()
    )
    if (
        grant is None or grant.status != "REDEEMED"
        or grant.selection_sequence != attempt_sequence
        or grant.incarnation != root.incarnation
        or grant.org_epoch != root.epoch
        or grant.target_epoch != target.epoch
        or selection.state not in {"SELECTED_UNWITNESSED", "WITNESSED"}
        or now.tzinfo is None or now >= selection.expires_at
    ):
        raise ReleaseConflict("stale or interrupted selection")
    subject = ReviewSubject.model_validate(grant.subject_body)
    if (
        subject.digest() != selection.subject_sha256.hex()
        or subject.org_id != org_id or subject.target_id != target_id
        or subject.incarnation != root.incarnation
        or subject.org_epoch != root.epoch
        or subject.target_epoch != target.epoch
        or subject.prior_published_revision != target.published_revision
    ):
        raise ReleaseConflict("subject facts do not match guarded selection")

    earlier_witness = "0" * 64
    if target.published_revision > 0:
        last = await session.scalar(
            select(ReleasePublication).where(
                ReleasePublication.org_id == org_id,
                ReleasePublication.target_id == target_id,
                ReleasePublication.published_revision == target.published_revision,
            )
        )
        if last is None:
            raise ReleaseConflict("missing predecessor publication")
        earlier_witness = last.witness_sha256.hex()
    if cert_body.predecessor_witness_sha256 != earlier_witness:
        raise ReleaseConflict("missing or incorrect predecessor certificate")

    vetostate = verify_veto(
        live_veto, pinned_key_der=pinned_veto_key_der, nonce=veto_nonce,
        org_id=org_id, incarnation=root.incarnation,
        minimum_root_generation=cert_body.security_root_generation,
        now=now,
    )
    snapshot = WitnessSelection(
        org_id=org_id, target_id=target_id,
        attempt_sequence=attempt_sequence,
        prior_published_revision=selection.prior_published_revision,
        subject_sha256=selection.subject_sha256.hex(),
        approval_set_sha256=grant.approval_set_sha256.hex(),
        staging_sha256=selection.staging_sha256.hex(),
        content_sha256=subject.content_sha256,
        delivery_profile_sha256=subject.delivery_profile_sha256,
        predecessor_witness_sha256=earlier_witness,
        selected_at=selection.created_at,
        expires_at=selection.expires_at,
    )
    digest = verify_witness_certificate(
        body=cert_body, signature=cert_signature,
        pinned_public_key_der=pinned_witness_key_der, selection=snapshot,
        incarnation=root.incarnation,
        root_generation=cert_body.security_root_generation,
        no_external_veto=True, now=now,
    )
    expected_key = (
        f"certificates/v1/{org_id.hex}/{root.incarnation.hex}/"
        f"{target_id.hex}/{attempt_sequence:020d}"
    )
    if (
        archive_ref.bucket != pinned_archive_bucket
        or archive_ref.key != expected_key
        or not archive_ref.version_id or archive_ref.version_id == "null"
        or not hmac.compare_digest(archive_ref.object_sha256, digest)
        or not hmac.compare_digest(
            exact_archive_bytes, signed_certificate_bytes(cert_body, cert_signature)
        )
    ):
        raise ReleaseConflict("independent immutable witness version is unverified")

    if selection.state == "WITNESSED":
        if (
            selection.witness_sha256 == bytes.fromhex(digest)
            and selection.witness_version_id == archive_ref.version_id
        ):
            return "WITNESSED"
        # Commit a local STOP on a conflicting witness rather than raising
        # and accidentally rolling back the emergency fence.
        target.guard = "STOP_SERVING"
        target.epoch += 1
        await record_event(
            session, org_id=org_id, actor_id=actor_id, stream="release",
            event_type="WITNESS_FORK_STOP_SERVING",
            body={"target_id": str(target_id), "attempt_sequence": attempt_sequence},
        )
        return "FORK_STOP_SERVING"

    selection.state = "WITNESSED"
    selection.witness_sha256 = bytes.fromhex(digest)
    selection.witness_version_id = archive_ref.version_id
    await record_event(
        session, org_id=org_id, actor_id=actor_id, stream="release",
        event_type="INDEPENDENT_WITNESS_REGISTERED",
        body={
            "target_id": str(target_id), "attempt_sequence": attempt_sequence,
            "witness_sha256": digest,
        },
    )
    return "WITNESSED"
