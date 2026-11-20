"""Audit checkpoint signature, predecessor and exact S3 version negative tests."""
from datetime import datetime, timezone
from uuid import uuid4
import io

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from aegentra.audit_checkpoint import (
    AuditCheckpoint, AuditCheckpointRejected, CheckpointArchive,
    checkpoint_message, verify_checkpoint, signed_checkpoint_bytes,
)


class FakeS3:
    def __init__(self):
        self.objects = {}
        self.version = "independent-archive-v1"
        self.put_calls = []
        self.get_calls = []

    def put_object(self, **kwargs):
        self.put_calls.append(kwargs)
        if kwargs["Key"] in self.objects:
            raise RuntimeError("PreconditionFailed")
        self.objects[kwargs["Key"]] = bytes(kwargs["Body"])
        return {"VersionId": self.version}

    def get_object(self, **kwargs):
        self.get_calls.append(kwargs)
        raw = self.objects[kwargs["Key"]]
        return {"Body": io.BytesIO(raw), "ContentLength": len(raw),
                "VersionId": self.version}


class FakeSTS:
    account = "123456789012"

    def get_caller_identity(self):
        return {"Account": self.account}


def fixture():
    now = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)
    org, inc = uuid4(), uuid4()
    body = AuditCheckpoint(
        kind="aegentra.security.audit-checkpoint.v1",
        audience="aegentra-immutable-audit-archive",
        org_id=org, incarnation=inc, stream="release",
        sequence=42, head_sha256="a" * 64,
        predecessor_checkpoint_sha256="b" * 64,
        root_generation=3, signer_key_id="security-audit-signing-key",
        issued_at=now,
    )
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    signature = key.sign(checkpoint_message(body), ec.ECDSA(hashes.SHA256()))
    return body, key, public, signature, now


def verify(body, public, signature, now):
    return verify_checkpoint(
        body=body, signature_der=signature, public_der=public,
        expected_key_id="security-audit-signing-key",
        org_id=body.org_id, incarnation=body.incarnation,
        stream="release", minimum_sequence=41,
        expected_predecessor_sha256="b" * 64,
        minimum_root_generation=3, now=now,
    )


def test_separately_signed_checkpoint_binds_stream_and_predecessor():
    body, key, public, signature, now = fixture()
    assert len(verify(body, public, signature, now)) == 64
    assert b"security.audit-checkpoint" in checkpoint_message(body)


@pytest.mark.parametrize("tamper", [
    "predecessor", "stream", "sequence", "root", "signature", "key",
])
def test_forked_or_replayed_audit_checkpoint_fails(tamper):
    body, key, public, signature, now = fixture()
    if tamper == "predecessor":
        body = body.model_copy(update={"predecessor_checkpoint_sha256": "c" * 64})
    elif tamper == "stream":
        body = body.model_copy(update={"stream": "cases"})
    elif tamper == "sequence":
        body = body.model_copy(update={"sequence": 41})
    elif tamper == "root":
        body = body.model_copy(update={"root_generation": 2})
    elif tamper == "signature":
        signature = key.sign(b"wrong signing purpose", ec.ECDSA(hashes.SHA256()))
    else:
        public = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    with pytest.raises(AuditCheckpointRejected):
        verify(body, public, signature, now)


def test_checkpoint_archive_requires_conditional_version_and_exact_bytes():
    body, key, public, signature, now = fixture()
    storage, sts = FakeS3(), FakeSTS()
    archive = CheckpointArchive(
        s3=storage, sts=sts, bucket="independent-audit",
        security_account_id="123456789012",
    )
    ref = archive.append(body, signature)
    assert storage.put_calls[0]["IfNoneMatch"] == "*"
    assert ref.version_id == "independent-archive-v1"
    assert archive.read_exact(ref, body=body) == signed_checkpoint_bytes(body, signature)
    assert storage.get_calls[0]["VersionId"] == ref.version_id
    with pytest.raises(RuntimeError):
        archive.append(body, signature)
    storage.objects[ref.key] += b"tamper"
    with pytest.raises(AuditCheckpointRejected):
        archive.read_exact(ref, body=body)


def test_wrong_account_and_wrong_version_do_not_prove_immutable_audit():
    body, key, public, signature, now = fixture()
    storage, sts = FakeS3(), FakeSTS()
    archive = CheckpointArchive(
        s3=storage, sts=sts, bucket="independent-audit",
        security_account_id="123456789012",
    )
    ref = archive.append(body, signature)
    sts.account = "000000000000"
    with pytest.raises(AuditCheckpointRejected):
        archive.read_exact(ref, body=body)
    sts.account = "123456789012"
    wrong = ref.__class__(ref.bucket, ref.key, "null", ref.sha256)
    with pytest.raises(AuditCheckpointRejected):
        archive.read_exact(wrong, body=body)
