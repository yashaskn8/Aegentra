"""Read-only AWS deletion inventory with exact NotFound semantics.

A missing AWS control-plane object is a cleanup hint only after the original
physical IDs, account, generation and independent read-only role are pinned.
AccessDenied, throttling, network errors and malformed responses never count
as deleted resources.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from aegentra.bridge_disposal import DeletedInventory, DisposalRejected


def _error_code(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return None
    error = response.get("Error")
    if not isinstance(error, dict) or not isinstance(error.get("Code"), str):
        return None
    return error["Code"]


def _instance_state(ec2: Any, instance_id: str) -> str:
    try:
        payload = ec2.describe_instances(InstanceIds=[instance_id])
    except Exception as exc:
        if _error_code(exc) == "InvalidInstanceID.NotFound":
            return "not-found"
        raise DisposalRejected("EC2 instance deletion cannot be verified") from exc
    if payload.get("NextToken"):
        raise DisposalRejected("unexamined EC2 instance inventory page")
    reservations = payload.get("Reservations")
    if not isinstance(reservations, list):
        raise DisposalRejected("malformed EC2 instance inventory")
    instances = []
    for group in reservations:
        if not isinstance(group, dict) or not isinstance(group.get("Instances"), list):
            raise DisposalRejected("malformed EC2 reservation inventory")
        instances.extend(group["Instances"])
    if len(instances) != 1 or not isinstance(instances[0], dict):
        raise DisposalRejected("missing or duplicated EC2 instance result")
    inst = instances[0]
    if inst.get("InstanceId") != instance_id:
        raise DisposalRejected("wrong EC2 physical instance identity")
    state = inst.get("State")
    if not isinstance(state, dict) or state.get("Name") != "terminated":
        raise DisposalRejected("EC2 instance not terminated")
    return "terminated"


def _volume_state(ec2: Any, volume_id: str) -> str:
    try:
        payload = ec2.describe_volumes(VolumeIds=[volume_id])
    except Exception as exc:
        if _error_code(exc) == "InvalidVolume.NotFound":
            return "not-found"
        raise DisposalRejected("EBS deletion cannot be verified") from exc
    if payload.get("NextToken"):
        raise DisposalRejected("unexamined EBS inventory page")
    volumes = payload.get("Volumes")
    if not isinstance(volumes, list):
        raise DisposalRejected("malformed EBS inventory")
    # The API answered normally; even 'deleting' remains a live resource.
    raise DisposalRejected("pinned EBS volume still exists or result is ambiguous")


def collect_deleted_inventory(
    *, ec2: Any, sts: Any, expected_account: str,
    instance_id: str, input_volume_id: str, output_volume_id: str,
    observed_at: datetime,
) -> DeletedInventory:
    if (
        observed_at.tzinfo is None or observed_at.utcoffset() is None
        or len(expected_account) != 12 or not expected_account.isdecimal()
        or not instance_id.startswith("i-")
        or not input_volume_id.startswith("vol-")
        or not output_volume_id.startswith("vol-")
        or input_volume_id == output_volume_id
    ):
        raise DisposalRejected("untrusted AWS cleanup inventory pins")
    try:
        account = sts.get_caller_identity()["Account"]
    except Exception as exc:
        raise DisposalRejected("cannot identify AWS inventory account") from exc
    if account != expected_account:
        raise DisposalRejected("AWS cleanup inventory collected in wrong account")
    state = _instance_state(ec2, instance_id)
    volumes = {
        volume_id: _volume_state(ec2, volume_id)
        for volume_id in (input_volume_id, output_volume_id)
    }
    return DeletedInventory(
        account_id=account, observed_at=observed_at,
        instance_id=instance_id, instance_state=state,
        volume_states=volumes,
    )
