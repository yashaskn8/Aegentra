"""Privileged publish commit: witnessed selection is not public until here.

The caller independently reads the exact S3 witness version and obtains a
separately signed origin binding and fresh veto BEFORE opening SERIALIZABLE.
The authority only writes a PENDING_SEAL publication; the gateway will not
serve it until its publication receipt is independently sealed.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegentra.audit import record_event
from aegentra.db import ReleaseGrant, ReleasePublication, ReleaseSelection
from aegentra.gateway_signatures import SignedVeto, verify_veto
from aegentra.origin_binding import OriginBinding, verify_origin_binding
from aegentra.release_state import ReleaseConflict, _locked
from aegentra.review_crypto import ReviewSubject
from aegentra.witness_crypto import (
    WitnessArchiveRef, WitnessBody, WitnessSelection,
    signed_certificate_bytes, verify_witness_certificate,
)


@dataclass(frozen=True)
class PublicationPendingSeal:
    published_revision: int
    attempt_sequence: int
    state: str = "PENDING_SEAL"


async def publish_witnessed_selection(
    session: AsyncSession, *,
    org_id: UUID, target_id: UUID, attempt_sequence: int,
    actor_id: UUID, now: datetime,
    witness: WitnessBody, witness_signature: bytes, witness_ref: WitnessArchiveRef,
    exact_witness_bytes: bytes, witness_public_der: bytes,
    security_veto: SignedVeto, veto_nonce: str, veto_public_der: bytes,
    origin_binding: OriginBinding, origin_signature: bytes,
    origin_verifier_public_der: bytes, origin_key_id: str,
    pinned_witness_bucket: str,
) -> PublicationPendingSeal:
    """One guarded publication revision, with immutable preverified inputs."""
    root, target = await _locked(session, org_id, target_id)
    if (
        target.mode != "ENFORCED" or target.guard != "ACTIVE"
        or not target.origin_bucket or not target.origin_key_prefix
        or not target.resource_path or now.tzinfo is None
    ):
        raise ReleaseConflict("target not qualified for protected publication")

    selection = await session.scalar(
        select(ReleaseSelection).where(
            ReleaseSelection.org_id == org_id,
            ReleaseSelection.target_id == target_id,
            ReleaseSelection.attempt_sequence == attempt_sequence,
        ).with_for_update()
    )
    if selection is None or selection.state != "WITNESSED":
        raise ReleaseConflict("no currently witnessed selection to publish")
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
        or selection.prior_published_revision != target.published_revision
        or now + timedelta(seconds=3) >= selection.expires_at
        or selection.witness_sha256 is None
        or not hmac.compare_digest(
            selection.witness_sha256, bytes.fromhex(witness_ref.object_sha256)
        )
        or selection.witness_version_id != witness_ref.version_id
    ):
        raise ReleaseConflict("selection has expired, forked or changed governance")

    subject = ReviewSubject.model_validate(grant.subject_body)
    if (
        subject.digest() != grant.subject_sha256.hex()
        or subject.resource_path != target.resource_path
        or subject.destination_host != target.destination_host
        or subject.org_epoch != root.epoch
        or subject.target_epoch != target.epoch
        or subject.prior_published_revision != target.published_revision
    ):
        raise ReleaseConflict("signed review subject no longer matches target")

    previous_witness_sha256 = "0" * 64
    if target.published_revision:
        previous = await session.scalar(
            select(ReleasePublication).where(
                ReleasePublication.org_id == org_id,
                ReleasePublication.target_id == target_id,
                ReleasePublication.published_revision == target.published_revision,
            )
        )
        if previous is None or previous.status != "SEALED":
            raise ReleaseConflict("previous publication receipt not sealed")
        previous_witness_sha256 = previous.witness_sha256.hex()

    veto = verify_veto(
        security_veto, pinned_key_der=veto_public_der,
        nonce=veto_nonce, org_id=org_id,
        incarnation=root.incarnation, now=now,
        minimum_root_generation=witness.security_root_generation,
    )
    origin = verify_origin_binding(
        binding=origin_binding, signature_der=origin_signature,
        pinned_verifier_der=origin_verifier_public_der,
        expected_key_id=origin_key_id, subject=subject,
        enrolled_bucket=target.origin_bucket,
        enrolled_key_prefix=target.origin_key_prefix, now=now,
    )
    selected = WitnessSelection(
        org_id=org_id, target_id=target_id,
        attempt_sequence=attempt_sequence,
        prior_published_revision=selection.prior_published_revision,
        subject_sha256=selection.subject_sha256.hex(),
        approval_set_sha256=grant.approval_set_sha256.hex(),
        staging_sha256=selection.staging_sha256.hex(),
        content_sha256=subject.content_sha256,
        delivery_profile_sha256=subject.delivery_profile_sha256,
        predecessor_witness_sha256=previous_witness_sha256,
        selected_at=selection.created_at,
        expires_at=selection.expires_at,
    )
    certificate_digest = verify_witness_certificate(
        body=witness, signature=witness_signature,
        pinned_public_key_der=witness_public_der,
        selection=selected, incarnation=root.incarnation,
        root_generation=witness.security_root_generation,
        no_external_veto=True, now=now,
    )
    exact_key = (
        f"certificates/v1/{org_id.hex}/{root.incarnation.hex}/"
        f"{target_id.hex}/{attempt_sequence:020d}"
    )
    if (
        witness_ref.bucket != pinned_witness_bucket
        or witness_ref.key != exact_key
        or witness_ref.version_id == "null"
        or certificate_digest != witness_ref.object_sha256
        or not hmac.compare_digest(
            exact_witness_bytes, signed_certificate_bytes(witness, witness_signature)
        )
    ):
        raise ReleaseConflict("independent witness object version differs")

    new_revision = target.published_revision + 1
    session.add(ReleasePublication(
        org_id=org_id, target_id=target_id,
        published_revision=new_revision,
        attempt_sequence=attempt_sequence,
        witness_version_id=witness_ref.version_id,
        witness_sha256=bytes.fromhex(certificate_digest),
        representation_sha256=bytes.fromhex(subject.content_sha256),
        delivery_profile_sha256=bytes.fromhex(subject.delivery_profile_sha256),
        origin_bucket=origin_binding.origin_bucket,
        origin_key=origin_binding.origin_key,
        origin_version_id=origin_binding.origin_version_id,
        status="PENDING_SEAL", created_at=now,
    ))
    target.published_revision = new_revision
    target.published_attempt_sequence = attempt_sequence
    selection.state = "PUBLISHED"
    await session.flush()
    await record_event(
        session, org_id=org_id, actor_id=actor_id,
        stream="release", event_type="PUBLICATION_PENDING_SEAL",
        body={
            "target_id": str(target_id),
            "attempt_sequence": attempt_sequence,
            "published_revision": new_revision,
            "witness_sha256": certificate_digest,
        },
    )
    return PublicationPendingSeal(
        published_revision=new_revision, attempt_sequence=attempt_sequence,
    )
