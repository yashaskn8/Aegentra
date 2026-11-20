"""Independent incident custodian: record CONTAINED only with checked STOP.

The browser/API role cannot execute this routine or update privileged case
states; PostgreSQL enforces a separate native role. The source proofs must
come from an independently controlled security-root and gateway enrollment.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import rfc8785
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegentra.audit import record_event
from aegentra.db import (
    IncidentContainmentReceipt, InvestigationCase,
    ReleaseOrgGuard, ReleaseTarget,
)
from aegentra.security_veto import SecurityRootState
from aegentra.stop_containment import (
    SignedFence, SignedGatewayAck, SignerCredential,
    assess_stop_containment,
)


class ContainmentStateRejected(ValueError):
    pass


@dataclass(frozen=True)
class ContainmentArchiveRef:
    bucket: str
    key: str
    version_id: str
    sha256: str


def containment_proof_bytes(
    *, root: SecurityRootState, root_version_id: str,
    authority_fence: SignedFence,
    gateway_acks: tuple[SignedGatewayAck, ...],
) -> bytes:
    """Canonical witness of every signed receipt; no private key material."""
    ordered = sorted(gateway_acks, key=lambda item: item.body.gateway_id)
    return rfc8785.dumps({
        "kind": "aegentra.incident.containment-proof.v1",
        "root": root.model_dump(mode="json"),
        "root_version_id": root_version_id,
        "fence": {
            "body": authority_fence.body.model_dump(mode="json"),
            "signature_der_hex": authority_fence.signature_der.hex(),
        },
        "gateway_acks": [{
            "body": item.body.model_dump(mode="json"),
            "signature_der_hex": item.signature_der.hex(),
        } for item in ordered],
    })


async def record_independent_containment(
    session: AsyncSession, *,
    org_id: UUID, case_id: UUID, target_id: UUID,
    actor_id: UUID, expected_revision: int,
    root: SecurityRootState, root_version_id: str,
    authority_fence: SignedFence, authority_key: SignerCredential,
    gateway_acks: tuple[SignedGatewayAck, ...],
    enrolled_gateways: dict[str, SignerCredential],
    archive_ref: ContainmentArchiveRef,
    exact_archive_bytes: bytes, pinned_archive_bucket: str,
    now: datetime,
) -> str:
    """No network I/O or fake acknowledgment inside the DB transaction."""
    if (
        now.tzinfo is None or not root_version_id or root_version_id == "null"
        or not isinstance(exact_archive_bytes, bytes)
        or not 0 < len(exact_archive_bytes) <= 64 * 1024
    ):
        raise ContainmentStateRejected("untrusted external incident evidence")
    if root.org_id != org_id:
        raise ContainmentStateRejected("wrong organization root")
    assessment = assess_stop_containment(
        root=root, target_id=target_id,
        authority_fence=authority_fence, authority_key=authority_key,
        gateway_acks=gateway_acks,
        enrolled_gateways=enrolled_gateways, now=now,
    )
    if not assessment.contained:
        raise ContainmentStateRejected("independent gateway containment not confirmed")
    proof = containment_proof_bytes(
        root=root, root_version_id=root_version_id,
        authority_fence=authority_fence, gateway_acks=gateway_acks,
    )
    expected_key = (
        f"incidents/v1/{org_id.hex}/{case_id.hex}/"
        f"{root.veto_generation:020d}"
    )
    digest = hashlib.sha256(proof).hexdigest()
    if (
        archive_ref.bucket != pinned_archive_bucket
        or archive_ref.key != expected_key
        or not archive_ref.version_id or archive_ref.version_id == "null"
        or not hmac.compare_digest(archive_ref.sha256, digest)
        or not hmac.compare_digest(exact_archive_bytes, proof)
    ):
        raise ContainmentStateRejected("incident archive version does not match signatures")

    # SERIALIZABLE caller reads root before target and case, then stores all
    # case+containment+audit/outbox changes in one primary DB transaction.
    installation = await session.scalar(
        select(ReleaseOrgGuard).where(
            ReleaseOrgGuard.org_id == org_id
        )
    )
    target = await session.scalar(
        select(ReleaseTarget).where(
            ReleaseTarget.org_id == org_id,
            ReleaseTarget.id == target_id,
        ).with_for_update()
    )
    case = await session.scalar(
        select(InvestigationCase).where(
            InvestigationCase.org_id == org_id,
            InvestigationCase.id == case_id,
        ).with_for_update()
    )
    if (
        installation is None or installation.incarnation != root.incarnation
        or target is None or target.asset_id != (case.asset_id if case else None)
        or target.guard != "STOP_SERVING"
        or case is None
    ):
        raise ContainmentStateRejected("local authority is not fenced for case target")
    old = await session.scalar(
        select(IncidentContainmentReceipt).where(
            IncidentContainmentReceipt.org_id == org_id,
            IncidentContainmentReceipt.case_id == case_id,
            IncidentContainmentReceipt.veto_generation == root.veto_generation,
        )
    )
    if old is not None:
        if (
            case.status == "CONTAINED"
            and old.archive_sha256 == bytes.fromhex(digest)
            and old.archive_version_id == archive_ref.version_id
        ):
            return "CONTAINED"
        raise ContainmentStateRejected("forked or contradictory containment evidence")
    if case.status != "CONTAINMENT_REQUESTED" or case.revision != expected_revision:
        raise ContainmentStateRejected("stale or non-requested case containment")
    case.status = "CONTAINED"
    case.revision += 1
    session.add(IncidentContainmentReceipt(
        org_id=org_id, case_id=case_id,
        veto_generation=root.veto_generation,
        target_id=target_id, incarnation=root.incarnation,
        root_version_id=root_version_id,
        archive_version_id=archive_ref.version_id,
        archive_sha256=bytes.fromhex(digest),
        gateway_count=len(gateway_acks),
        recorded_by=actor_id, recorded_at=now,
    ))
    await session.flush()
    await record_event(
        session, org_id=org_id, actor_id=actor_id,
        stream="cases", event_type="INCIDENT_CONTAINMENT_VERIFIED",
        body={
            "case_id": str(case_id), "target_id": str(target_id),
            "veto_generation": root.veto_generation,
            "archive_sha256": digest, "case_revision": case.revision,
        },
    )
    return "CONTAINED"
