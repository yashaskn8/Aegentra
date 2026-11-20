"""Read-only primary-head service and independently pinned AWS KMS signer.

Do not expose this routine through the browser BFF or a public endpoint.
It must run under a separately authorized native authority identity, with
a fixed gateway machine audience and verified mTLS ingress.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegentra.db import ReleaseOrgGuard, ReleasePublication, ReleaseTarget
from aegentra.gateway_signatures import (
    AdmissionDenied, HeadSnapshot, SignedHead, head_message,
    _verify_pinned_key,
)
from aegentra.release_state import ReleaseConflict


def generate_fresh_head(
    *,
    root: ReleaseOrgGuard, target: ReleaseTarget,
    publication: ReleasePublication, witness_bucket: str,
    request_nonce: str, now: datetime,
) -> HeadSnapshot:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ReleaseConflict("primary authority has no trusted UTC clock")
    if (
        root.org_id != target.org_id
        or target.org_id != publication.org_id
        or target.id != publication.target_id
        or target.mode != "ENFORCED"
        or target.guard == "STOP_SERVING"
        or not target.resource_path or not target.destination_host
        or not target.origin_bucket or not target.origin_key_prefix
        or target.published_revision < 1
        or target.published_revision != publication.published_revision
        or target.published_attempt_sequence != publication.attempt_sequence
        or publication.status != "SEALED"
        or not publication.receipt_version_id
        or not publication.receipt_sha256
        or publication.origin_bucket != target.origin_bucket
        or not publication.origin_key
        or not publication.origin_key.startswith(target.origin_key_prefix)
        or not publication.origin_version_id
        or publication.origin_version_id == "null"
        or not witness_bucket
        or not request_nonce or len(request_nonce) != 43
    ):
        raise ReleaseConflict("no independently sealed published head")

    timestamp = now.astimezone(timezone.utc)
    return HeadSnapshot(
        kind="aegentra.authority.head.v1",
        audience="aegentra-protected-gateway",
        request_nonce=request_nonce,
        incarnation=root.incarnation, org_id=root.org_id,
        target_id=target.id, destination_host=target.destination_host,
        resource_path=target.resource_path,
        mode=target.mode, guard=target.guard,
        published_revision=publication.published_revision,
        attempt_sequence=publication.attempt_sequence,
        content_sha256=publication.representation_sha256.hex(),
        delivery_profile_sha256=publication.delivery_profile_sha256.hex(),
        witness_bucket=witness_bucket,
        witness_key=(
            f"certificates/v1/{root.org_id.hex}/{root.incarnation.hex}/"
            f"{target.id.hex}/{publication.attempt_sequence:020d}"
        ),
        witness_version_id=publication.witness_version_id,
        witness_sha256=publication.witness_sha256.hex(),
        origin_bucket=publication.origin_bucket,
        origin_key=publication.origin_key,
        origin_version_id=publication.origin_version_id,
        issued_at=timestamp, expires_at=timestamp + timedelta(seconds=1),
    )


async def read_primary_head(
    session: AsyncSession, *,
    org_id: UUID, target_id: UUID, witness_bucket: str,
    nonce: str, now: datetime,
) -> HeadSnapshot:
    """Fresh database read (caller must connect to primary, never a cache)."""
    root = await session.scalar(
        select(ReleaseOrgGuard).where(ReleaseOrgGuard.org_id == org_id)
    )
    target = await session.scalar(
        select(ReleaseTarget).where(
            ReleaseTarget.org_id == org_id, ReleaseTarget.id == target_id,
        )
    )
    if root is None or target is None:
        raise ReleaseConflict("target root unavailable")
    publication = await session.scalar(
        select(ReleasePublication).where(
            ReleasePublication.org_id == org_id,
            ReleasePublication.target_id == target_id,
            ReleasePublication.published_revision == target.published_revision,
        )
    )
    if publication is None:
        raise ReleaseConflict("sealed publication unavailable")
    return generate_fresh_head(
        root=root, target=target, publication=publication,
        witness_bucket=witness_bucket, request_nonce=nonce, now=now,
    )


class KmsHeadSigner:
    """Native KMS ECDSA_SHA_256, fixed key ID and independently pinned public key."""

    def __init__(self, *, kms: Any, key_id: str, public_der: bytes):
        if not key_id or len(key_id) > 256:
            raise ValueError("a configured KMS signing key ID is required")
        self.kms, self.key_id, self.public_der = kms, key_id, public_der

    def sign(self, head: HeadSnapshot) -> SignedHead:
        message = head_message(head)
        if len(message) > 4096:
            raise ReleaseConflict("head exceeds KMS raw signing bound")
        response = self.kms.sign(
            KeyId=self.key_id,
            Message=message,
            MessageType="RAW",
            SigningAlgorithm="ECDSA_SHA_256",
        )
        signature = response.get("Signature")
        if not isinstance(signature, bytes):
            raise ReleaseConflict("KMS signature unavailable")
        _verify_pinned_key(self.public_der, signature, message)
        return SignedHead(head, signature)
