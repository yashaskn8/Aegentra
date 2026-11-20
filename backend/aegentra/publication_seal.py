"""Record the separately signed, immutable publication receipt.

Unsealed publication rows are intentionally not eligible for a signed
protected head. A changed receipt at an existing revision fences the target.
"""
from __future__ import annotations

import hmac
from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegentra.audit import record_event
from aegentra.db import ReleasePublication
from aegentra.publication_archive import PublicationArchiveRef
from aegentra.publication_receipt import (
    PublicationReceipt, signed_publication_receipt_bytes,
    verify_publication_receipt,
)
from aegentra.release_state import ReleaseConflict, _locked


async def seal_publication_receipt(
    session: AsyncSession, *,
    org_id: UUID, target_id: UUID, published_revision: int,
    actor_id: UUID,
    body: PublicationReceipt, signature_der: bytes,
    public_key_der: bytes, expected_signer_key_id: str,
    archive_ref: PublicationArchiveRef, exact_archive_bytes: bytes,
    enrolled_archive_bucket: str, now: datetime,
) -> str:
    root, target = await _locked(session, org_id, target_id)
    if now.tzinfo is None or target.published_revision < published_revision:
        raise ReleaseConflict("publication not committed or trusted time unavailable")
    publication = await session.scalar(
        select(ReleasePublication).where(
            ReleasePublication.org_id == org_id,
            ReleasePublication.target_id == target_id,
            ReleasePublication.published_revision == published_revision,
        ).with_for_update()
    )
    if publication is None:
        raise ReleaseConflict("no publication receipt to seal")
    digest = verify_publication_receipt(
        body=body, signature_der=signature_der,
        pinned_public_der=public_key_der,
        expected_key_id=expected_signer_key_id,
        publication=publication,
        incarnation=root.incarnation, now=now,
    )
    key = (
        f"publications/v1/{org_id.hex}/{root.incarnation.hex}/"
        f"{target_id.hex}/{published_revision:020d}"
    )
    if (
        archive_ref.bucket != enrolled_archive_bucket
        or archive_ref.key != key or not archive_ref.version_id
        or archive_ref.version_id == "null"
        or not hmac.compare_digest(archive_ref.sha256, digest)
        or not hmac.compare_digest(
            exact_archive_bytes, signed_publication_receipt_bytes(body, signature_der)
        )
    ):
        raise ReleaseConflict("exact publication archive version not verified")

    if publication.status == "SEALED":
        if (
            publication.receipt_version_id == archive_ref.version_id
            and publication.receipt_sha256 == bytes.fromhex(digest)
        ):
            return "SEALED"
        target.guard = "STOP_SERVING"
        target.epoch += 1
        await record_event(
            session, org_id=org_id, actor_id=actor_id,
            stream="release", event_type="PUBLICATION_RECEIPT_FORK_STOP",
            body={
                "target_id": str(target_id),
                "published_revision": published_revision,
            },
        )
        return "FORK_STOP_SERVING"

    if publication.status != "PENDING_SEAL":
        raise ReleaseConflict("unknown publication state")
    publication.receipt_sha256 = bytes.fromhex(digest)
    publication.receipt_version_id = archive_ref.version_id
    publication.status = "SEALED"
    await record_event(
        session, org_id=org_id, actor_id=actor_id,
        stream="release", event_type="PUBLICATION_RECEIPT_SEALED",
        body={
            "target_id": str(target_id),
            "published_revision": published_revision,
            "receipt_sha256": digest,
        },
    )
    return "SEALED"
