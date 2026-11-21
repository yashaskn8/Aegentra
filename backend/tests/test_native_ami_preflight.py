"""Private AMI and root-snapshot checks must fail closed."""
from copy import deepcopy

import pytest

from aegentra.native_ami_preflight import AmiPin, AmiRejected, verify_native_ami


class STS:
    account = "123456789012"

    def get_caller_identity(self):
        return {"Account": self.account}


class EC2:
    def __init__(self, pin):
        self.calls = []
        self.fail_at = None
        self.image = {
            "ImageId": pin.ami_id,
            "OwnerId": pin.image_owner_id,
            "State": "available",
            "Public": False,
            "ImageType": "machine",
            "RootDeviceType": "ebs",
            "VirtualizationType": "hvm",
            "Architecture": "x86_64",
            "EnaSupport": True,
            "RootDeviceName": "/dev/xvda",
            "BlockDeviceMappings": [{
                "DeviceName": "/dev/xvda",
                "Ebs": {
                    "SnapshotId": pin.root_snapshot_id,
                    "VolumeSize": 8,
                    "DeleteOnTermination": True,
                },
            }],
        }
        self.snapshot = {
            "SnapshotId": pin.root_snapshot_id,
            "OwnerId": pin.snapshot_owner_id,
            "State": "completed",
            "Encrypted": True,
            "KmsKeyId": pin.kms_key_arn,
            "VolumeSize": 8,
        }
        self.image_page = None
        self.snapshot_page = None

    def describe_images(self, **kwargs):
        self.calls.append(("describe_images", kwargs))
        if self.fail_at == "images":
            raise OSError("fail closed")
        return {"Images": [deepcopy(self.image)], "NextToken": self.image_page}

    def describe_snapshots(self, **kwargs):
        self.calls.append(("describe_snapshots", kwargs))
        if self.fail_at == "snapshots":
            raise OSError("fail closed")
        return {"Snapshots": [deepcopy(self.snapshot)], "NextToken": self.snapshot_page}


def fixture():
    pin = AmiPin(
        analysis_account_id="123456789012",
        image_owner_id="123456789012",
        snapshot_owner_id="123456789012",
        ami_id="ami-00000000000000001",
        root_snapshot_id="snap-00000000000000001",
        kms_key_arn="arn:aws:kms:us-east-1:123456789012:key/verified",
        region="us-east-1",
    )
    return pin, EC2(pin), STS()


def test_exact_private_encrypted_root_candidate_has_no_launch_authority():
    pin, ec2, sts = fixture()
    result = verify_native_ami(ec2=ec2, sts=sts, pin=pin)
    assert result.ami_id == pin.ami_id
    assert result.status == "EXTERNAL_PROVENANCE_AND_ISOLATION_DRILLS_REQUIRED"
    assert ec2.calls == [
        ("describe_images", {"ImageIds": [pin.ami_id], "Owners": [pin.image_owner_id]}),
        ("describe_snapshots", {"SnapshotIds": [pin.root_snapshot_id]}),
    ]


def test_wrong_account_blocks_all_ec2_calls():
    pin, ec2, sts = fixture()
    sts.account = "000000000000"
    with pytest.raises(AmiRejected, match="wrong AWS account"):
        verify_native_ami(ec2=ec2, sts=sts, pin=pin)
    assert ec2.calls == []


@pytest.mark.parametrize("tamper", [
    "public", "wrong_owner", "wrong_image", "pending", "extra_volume",
    "instance_store", "wrong_snapshot", "wrong_snapshot_owner",
    "unencrypted", "wrong_kms", "snapshot_pending", "root_not_deleted",
    "big_root", "wrong_arch", "imds_unsupported", "image_page",
    "snapshot_page", "image_error", "snapshot_error",
])
def test_unsafe_or_unavailable_ami_evidence_is_rejected(tamper):
    pin, ec2, sts = fixture()
    if tamper == "public":
        ec2.image["Public"] = True
    elif tamper == "wrong_owner":
        ec2.image["OwnerId"] = "000000000000"
    elif tamper == "wrong_image":
        ec2.image["ImageId"] = "ami-00000000000000002"
    elif tamper == "pending":
        ec2.image["State"] = "pending"
    elif tamper == "extra_volume":
        ec2.image["BlockDeviceMappings"].append({"DeviceName": "/dev/xvdf"})
    elif tamper == "instance_store":
        ec2.image["RootDeviceType"] = "instance-store"
    elif tamper == "wrong_snapshot":
        ec2.image["BlockDeviceMappings"][0]["Ebs"]["SnapshotId"] = "snap-unpinned"
    elif tamper == "wrong_snapshot_owner":
        ec2.snapshot["OwnerId"] = "000000000000"
    elif tamper == "unencrypted":
        ec2.snapshot["Encrypted"] = False
    elif tamper == "wrong_kms":
        ec2.snapshot["KmsKeyId"] = "arn:aws:kms:us-east-1:123456789012:key/unexpected"
    elif tamper == "snapshot_pending":
        ec2.snapshot["State"] = "pending"
    elif tamper == "root_not_deleted":
        ec2.image["BlockDeviceMappings"][0]["Ebs"]["DeleteOnTermination"] = False
    elif tamper == "big_root":
        ec2.image["BlockDeviceMappings"][0]["Ebs"]["VolumeSize"] = 100
    elif tamper == "wrong_arch":
        ec2.image["Architecture"] = "arm64"
    elif tamper == "imds_unsupported":
        ec2.image["EnaSupport"] = False
    elif tamper == "image_page":
        ec2.image_page = "more"
    elif tamper == "snapshot_page":
        ec2.snapshot_page = "more"
    elif tamper == "image_error":
        ec2.fail_at = "images"
    else:
        ec2.fail_at = "snapshots"
    with pytest.raises(AmiRejected):
        verify_native_ami(ec2=ec2, sts=sts, pin=pin)


def test_unpinned_ami_or_kms_key_is_rejected_before_ec2():
    pin, ec2, sts = fixture()
    from dataclasses import replace
    with pytest.raises(AmiRejected):
        verify_native_ami(ec2=ec2, sts=sts, pin=replace(pin, ami_id="ami-latest"))
    with pytest.raises(AmiRejected):
        verify_native_ami(
            ec2=ec2, sts=sts,
            pin=replace(pin, kms_key_arn="alias/aws/ebs"),
        )
    assert ec2.calls == []
