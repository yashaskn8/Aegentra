"""Read-only native AWS inventory for detached, terminated analysis attempts.

The bridge uses its independent read-only EC2/STS credentials; no launch,
termination, delete, guest execution, or DB write is performed here.
The returned snapshot is necessary custody evidence, not isolation approval.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from aegentra.bridge_custody import (
    AttemptCustody, CustodyError, DetachedInventory, verify_detached_attempt,
)


def collect_detached_inventory(
    *, ec2: Any, sts: Any, expected: AttemptCustody,
) -> DetachedInventory:
    """Fetch precisely the three journaled resources; reject partial AWS results."""
    started = datetime.now(timezone.utc)
    try:
        account = sts.get_caller_identity()["Account"]
    except Exception as exc:
        raise CustodyError("cannot identify detached inventory AWS account") from exc
    if account != expected.account_id:
        raise CustodyError("AWS account differs from the durable custody journal")

    try:
        response = ec2.describe_instances(InstanceIds=[expected.instance_id])
        if not isinstance(response, dict) or response.get("NextToken"):
            raise CustodyError("partial EC2 instance inventory")
        reservations = response.get("Reservations")
        if not isinstance(reservations, list) or len(reservations) != 1:
            raise CustodyError("missing or ambiguous EC2 instance inventory")
        reservation = reservations[0]
        if not isinstance(reservation, dict):
            raise CustodyError("malformed EC2 reservation")
        instances = reservation.get("Instances")
        if (
            not isinstance(instances, list) or len(instances) != 1
            or not isinstance(instances[0], dict)
        ):
            raise CustodyError("missing or ambiguous EC2 instance")

        response = ec2.describe_volumes(VolumeIds=[
            expected.input_volume_id, expected.output_volume_id,
        ])
        if not isinstance(response, dict) or response.get("NextToken"):
            raise CustodyError("partial EBS volume inventory")
        volumes = response.get("Volumes")
        if (
            not isinstance(volumes, list) or len(volumes) != 2
            or any(not isinstance(v, dict) for v in volumes)
        ):
            raise CustodyError("missing or ambiguous EBS volumes")
    except CustodyError:
        raise
    except Exception as exc:
        raise CustodyError("detached native AWS inventory unavailable") from exc

    finished = datetime.now(timezone.utc)
    if finished < started or finished - started > timedelta(seconds=10):
        raise CustodyError("AWS inventory acquisition exceeded freshness budget")
    verify_detached_attempt(
        expected=expected, observed_account_id=account,
        instances=instances, volumes=volumes,
    )
    return DetachedInventory(
        account_id=account, observed_at=finished,
        instances=tuple(instances), volumes=tuple(volumes),
    )
