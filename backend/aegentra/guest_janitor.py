"""Native AWS janitor for two previously detached, pinned EBS volumes.

This function emits deletion requests only. It must never mark database
DISPOSED or claim a guest's sensitive bytes have vanished from AWS.
Use a narrow, separately provisioned native bridge AWS identity.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aegentra.bridge_custody import AttemptCustody, verify_detached_attempt


class JanitorUnknown(ValueError):
    """At least one destructive AWS request may have run; reconcile externally."""


@dataclass(frozen=True)
class JanitorRequests:
    volume_ids: tuple[str, str]
    status: str = "DELETION_REQUESTED_PENDING_INDEPENDENT_INVENTORY"


def request_detached_volume_deletion(
    *,
    ec2: Any, expected: AttemptCustody,
    observed_account: str,
    terminated_instances: list[dict],
    detached_volumes: list[dict],
) -> JanitorRequests:
    """Only the two journaled volumes can be requested for deletion."""
    verify_detached_attempt(
        expected=expected,
        observed_account_id=observed_account,
        instances=terminated_instances,
        volumes=detached_volumes,
    )
    # Record a full resource journal and validated receipt *before*
    # calling this method. Callers must persist intent separately.
    try:
        ec2.delete_volume(VolumeId=expected.input_volume_id)
        ec2.delete_volume(VolumeId=expected.output_volume_id)
    except Exception as exc:
        raise JanitorUnknown(
            "EBS deletion incomplete or unknown; preserve journal and quarantine"
        ) from exc
    return JanitorRequests(
        volume_ids=(expected.input_volume_id, expected.output_volume_id),
    )
