"""Protected head can only be signed from a sealed current revision."""
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from aegentra.db import ReleaseOrgGuard, ReleasePublication, ReleaseTarget
from aegentra.gateway_signatures import verify_head
from aegentra.head_service import KmsHeadSigner, generate_fresh_head
from aegentra.release_state import ReleaseConflict


class FakeKMS:
    def __init__(self, key):
        self.key = key
        self.calls = []

    def sign(self, **kwargs):
        self.calls.append(kwargs)
        return {"Signature": self.key.sign(kwargs["Message"], ec.ECDSA(hashes.SHA256()))}


def fixture():
    org, target_id, inc = uuid4(), uuid4(), uuid4()
    timestamp = datetime.now(timezone.utc)
    root = ReleaseOrgGuard(org_id=org, incarnation=inc, epoch=1)
    target = ReleaseTarget(
        org_id=org, id=target_id, asset_id=uuid4(),
        destination_host="origin.example.test", resource_path="/index.html",
        mode="ENFORCED", guard="ACTIVE", epoch=1,
        origin_bucket="pinned-origin", origin_key_prefix="published/trusted/",
        next_attempt_sequence=1, published_revision=1,
        published_attempt_sequence=1,
    )
    publication = ReleasePublication(
        org_id=org, target_id=target_id, attempt_sequence=1,
        published_revision=1, witness_version_id="object-v1",
        witness_sha256=b"w" * 32, representation_sha256=b"b" * 32,
        delivery_profile_sha256=b"p" * 32, fixed_bundle_sha256=b"q" * 32, created_at=timestamp,
        status="SEALED", receipt_version_id="receipt-v1",
        receipt_sha256=b"r" * 32, origin_bucket="pinned-origin",
        origin_key="published/trusted/html",
        origin_version_id="exact-version-2",
    )
    return root, target, publication, timestamp


def test_kms_signs_fresh_head_with_distinct_pinned_key():
    root, target, publication, now = fixture()
    head = generate_fresh_head(
        root=root, target=target, publication=publication,
        witness_bucket="security-bucket", request_nonce="n" * 43, now=now,
    )
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    kms = FakeKMS(private)
    signed = KmsHeadSigner(kms=kms, key_id="pinned-test-key", public_der=public).sign(head)
    assert kms.calls[0]["MessageType"] == "RAW"
    assert kms.calls[0]["SigningAlgorithm"] == "ECDSA_SHA_256"
    assert verify_head(
        signed, pinned_key_der=public, nonce="n" * 43,
        org_id=root.org_id, target_id=target.id,
        incarnation=root.incarnation, host=target.destination_host,
        path=target.resource_path, now=now,
    ) == head


@pytest.mark.parametrize("change", [
    "shadow", "stop", "unsealed", "old_revision", "wrong_bucket",
    "missing_receipt", "missing_origin", "missing_bundle",
])
def test_protected_head_fails_closed_when_release_unqualified(change):
    root, target, publication, now = fixture()
    if change == "shadow":
        target.mode = "SHADOW"
    elif change == "stop":
        target.guard = "STOP_SERVING"
    elif change == "unsealed":
        publication.status = "PENDING_SEAL"
    elif change == "old_revision":
        target.published_revision = 2
    elif change == "wrong_bucket":
        publication.origin_bucket = "other-bucket"
    elif change == "missing_receipt":
        publication.receipt_version_id = None
    elif change == "missing_bundle":
        publication.fixed_bundle_sha256 = None
    else:
        publication.origin_version_id = None
    with pytest.raises(ReleaseConflict):
        generate_fresh_head(
            root=root, target=target, publication=publication,
            witness_bucket="security-bucket",
            request_nonce="n" * 43, now=now,
        )


def test_held_target_can_serve_previous_sealed_release():
    root, target, publication, now = fixture()
    target.guard = "HOLD_PROMOTION"
    head = generate_fresh_head(
        root=root, target=target, publication=publication,
        witness_bucket="security-bucket", request_nonce="n" * 43, now=now,
    )
    assert head.guard == "HOLD_PROMOTION"
    assert head.published_revision == 1
