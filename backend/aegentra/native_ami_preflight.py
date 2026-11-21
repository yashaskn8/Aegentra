"""Read-only exact AMI and encrypted root-snapshot checks for offline guests.

This is a necessary AWS inventory check, NOT image provenance, a trusted
toolchain signature, or permission to launch a native EC2 guest.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any


class AmiRejected(ValueError):
    pass


@dataclass(frozen=True)
class AmiPin:
    analysis_account_id: str
    ami_id: str
    image_owner_id: str
    root_snapshot_id: str
    snapshot_owner_id: str
    kms_key_arn: str
    region: str

    def validate(self) -> None:
        for account in (
            self.analysis_account_id, self.image_owner_id, self.snapshot_owner_id,
        ):
            if re.fullmatch(r"[0-9]{12}", account) is None:
                raise AmiRejected("AMI inventory account pins are invalid")
        if (
            re.fullmatch(r"ami-[0-9a-f]{8,17}", self.ami_id) is None
            or re.fullmatch(r"snap-[0-9a-f]{8,17}", self.root_snapshot_id) is None
            or re.fullmatch(r"[a-z]{2}(-gov)?-[a-z0-9-]+-[0-9]", self.region) is None
            or not self.kms_key_arn.startswith(
                f"arn:aws:kms:{self.region}:{self.analysis_account_id}:key/"
            )
            or len(self.kms_key_arn) > 256
        ):
            raise AmiRejected("AMI identity, region or encryption key pin is invalid")


@dataclass(frozen=True)
class AmiCandidate:
    ami_id: str
    root_snapshot_id: str
    status: str = "EXTERNAL_PROVENANCE_AND_ISOLATION_DRILLS_REQUIRED"


def _one_inventory(payload: Any, name: str, resource: str) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("NextToken") not in (None, ""):
        raise AmiRejected("incomplete or malformed AWS AMI inventory")
    found = payload.get(name)
    if not isinstance(found, list) or len(found) != 1 or not isinstance(found[0], dict):
        raise AmiRejected(f"missing or ambiguous {resource}")
    return found[0]


def verify_native_ami(
    *, ec2: Any, sts: Any, pin: AmiPin,
) -> AmiCandidate:
    """Read only pinned image and snapshot properties; reject ambiguous results."""
    pin.validate()
    started = datetime.now(timezone.utc)
    try:
        account = sts.get_caller_identity()["Account"]
    except Exception as exc:
        raise AmiRejected("AWS AMI inventory account unavailable") from exc
    if account != pin.analysis_account_id:
        raise AmiRejected("AMI inventory came from wrong AWS account")
    try:
        image = _one_inventory(
            ec2.describe_images(
                ImageIds=[pin.ami_id], Owners=[pin.image_owner_id],
            ),
            "Images", "AMI image",
        )
        mappings = image.get("BlockDeviceMappings")
        if (
            image.get("ImageId") != pin.ami_id
            or image.get("OwnerId") != pin.image_owner_id
            or image.get("State") != "available"
            or image.get("Public") is not False
            or image.get("ImageType") != "machine"
            or image.get("RootDeviceType") != "ebs"
            or image.get("VirtualizationType") != "hvm"
            or image.get("Architecture") != "x86_64"
            or image.get("EnaSupport") is not True
            or not isinstance(mappings, list) or len(mappings) != 1
            or not isinstance(mappings[0], dict)
            or mappings[0].get("DeviceName") != image.get("RootDeviceName")
        ):
            raise AmiRejected("unqualified or ambiguous native guest AMI")
        ebs = mappings[0].get("Ebs")
        if (
            not isinstance(ebs, dict)
            or ebs.get("SnapshotId") != pin.root_snapshot_id
            or ebs.get("DeleteOnTermination") is not True
            or type(ebs.get("VolumeSize")) is not int
            or not 8 <= ebs["VolumeSize"] <= 16
        ):
            raise AmiRejected("AMI has an unpinned or unsafe root device")
        snapshot = _one_inventory(
            ec2.describe_snapshots(SnapshotIds=[pin.root_snapshot_id]),
            "Snapshots", "AMI root snapshot",
        )
        if (
            snapshot.get("SnapshotId") != pin.root_snapshot_id
            or snapshot.get("OwnerId") != pin.snapshot_owner_id
            or snapshot.get("State") != "completed"
            or snapshot.get("Encrypted") is not True
            or snapshot.get("KmsKeyId") != pin.kms_key_arn
            or snapshot.get("VolumeSize") != ebs["VolumeSize"]
        ):
            raise AmiRejected("AMI root snapshot is unpinned or unencrypted")
    except AmiRejected:
        raise
    except Exception as exc:
        raise AmiRejected("native AMI inventory unavailable") from exc
    ended = datetime.now(timezone.utc)
    if ended < started or ended - started > timedelta(seconds=10):
        raise AmiRejected("AMI inventory exceeded ten-second freshness budget")
    return AmiCandidate(pin.ami_id, pin.root_snapshot_id)
