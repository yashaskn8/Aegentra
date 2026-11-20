"""Independent fixed HTML+JS bundle: exact version, hash and typed signature."""
from datetime import datetime, timedelta, timezone
import hashlib
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from aegentra.fixed_delivery import FixedStaticProfile
from aegentra.fixed_bundle import (
    BundleRejected, FixedBundleAttestation, PinnedOriginObject,
    bundle_message, verify_fixed_bundle_versions, verify_fixed_bundle_attestation,
)


class Reader:
    def __init__(self, *, version: str, data: bytes):
        self.version, self.data = version, data
        self.calls = []

    def chunks(self, version_id):
        self.calls.append(version_id)
        if version_id != self.version:
            raise AssertionError("mutable/latest version read")
        middle = len(self.data) // 2
        yield self.data[:middle]
        yield self.data[middle:]


def fixture():
    source = b"const expected = 42;"
    profile = FixedStaticProfile(
        host="protected.example.test",
        script_sha256=hashlib.sha256(source).hexdigest(),
        script_length=len(source),
    )
    entry = PinnedOriginObject(
        bucket="original-bucket", key="published/test/entry",
        version_id="immutable-entry-v1",
    )
    script = PinnedOriginObject(
        bucket="original-bucket", key="published/test/script",
        version_id="immutable-script-v2",
    )
    er = Reader(version=entry.version_id, data=profile.generated_html())
    sr = Reader(version=script.version_id, data=source)
    return profile, entry, script, er, sr


def verify(profile, entry, script, er, sr, **kwargs):
    return verify_fixed_bundle_versions(
        profile=profile, entry=entry, script=script,
        pinned_bucket="original-bucket", pinned_prefix="published/test/",
        entry_reader=er, script_reader=sr, **kwargs,
    )


def test_both_original_versions_required_and_manifest_is_deterministic():
    profile, entry, script, er, sr = fixture()
    verified = verify(profile, entry, script, er, sr)
    assert er.calls == ["immutable-entry-v1"]
    assert sr.calls == ["immutable-script-v2"]
    assert len(verified.source_identity()) == 64
    assert verified.bundle_manifest_sha256 == profile.manifest_sha256()
    assert verified.storage_manifest_sha256 == verify(
        profile, entry, script, er, sr
    ).storage_manifest_sha256


@pytest.mark.parametrize("change", [
    "entry_bytes", "script_bytes", "bucket", "key", "version", "same_key",
])
def test_no_missing_altered_or_redirected_version_is_approved(change):
    profile, entry, script, er, sr = fixture()
    if change == "entry_bytes":
        er.data = er.data + b"<script></script>"
    elif change == "script_bytes":
        sr.data = sr.data.replace(b"42", b"43")
    elif change == "bucket":
        entry = entry.model_copy(update={"bucket": "attacker-bucket"})
    elif change == "key":
        script = script.model_copy(update={"key": "other/asset"})
    elif change == "version":
        entry = entry.model_copy(update={"version_id": "null"})
    else:
        script = script.model_copy(update={"key": entry.key})
    with pytest.raises(BundleRejected):
        verify(profile, entry, script, er, sr)


def signed_fixture():
    profile, entry, script, er, sr = fixture()
    verified = verify(profile, entry, script, er, sr)
    org, target, incarnation = uuid4(), uuid4(), uuid4()
    now = datetime.now(timezone.utc)
    body = FixedBundleAttestation(
        kind="aegentra.independent.fixed-bundle.v1",
        audience="aegentra-release-review", org_id=org,
        target_id=target, incarnation=incarnation, host=profile.host,
        template_version=profile.template_version,
        entry_path=profile.entry_path, script_path=profile.script_path,
        entry_sha256=hashlib.sha256(profile.generated_html()).hexdigest(),
        script_sha256=profile.script_sha256,
        script_length=profile.script_length,
        bundle_manifest_sha256=verified.bundle_manifest_sha256,
        storage_manifest_sha256=verified.storage_manifest_sha256,
        entry=entry, script=script,
        verifier_key_id="independent-bundle-verifier",
        issued_at=now, expires_at=now + timedelta(seconds=90),
    )
    signer = ec.generate_private_key(ec.SECP256R1())
    pub = signer.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    sig = signer.sign(bundle_message(body), ec.ECDSA(hashes.SHA256()))
    return verified, body, sig, pub, org, target, incarnation, now, signer


def checked(verified, body, sig, pub, org, target, incarnation, now, signer):
    return verify_fixed_bundle_attestation(
        body=body, signature_der=sig, verified=verified,
        public_key_der=pub, expected_key_id="independent-bundle-verifier",
        org_id=org, target_id=target, incarnation=incarnation, now=now,
    )


def test_distinct_signed_two_object_identity_is_verified():
    args = signed_fixture()
    assert len(checked(*args)) == 64


@pytest.mark.parametrize("change", [
    "wrong_key", "wrong_signature_purpose", "changed_script",
    "changed_storage", "wrong_target", "expired", "wrong_audience",
])
def test_invalid_or_replayed_bundle_proof_is_rejected(change):
    args = list(signed_fixture())
    if change == "wrong_key":
        args[3] = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    elif change == "wrong_signature_purpose":
        args[2] = args[8].sign(
            b"aegentra.security.witness.signature.v1\x00" + args[1].canonical(),
            ec.ECDSA(hashes.SHA256()),
        )
    elif change == "changed_script":
        args[1] = args[1].model_copy(update={"script_sha256": "9" * 64})
    elif change == "changed_storage":
        args[1] = args[1].model_copy(update={"storage_manifest_sha256": "8" * 64})
    elif change == "wrong_target":
        args[5] = uuid4()
    elif change == "expired":
        args[7] += timedelta(seconds=120)
    else:
        args[1] = args[1].model_copy(update={"audience": "other-review"})
    with pytest.raises((BundleRejected, ValueError)):
        checked(*args)
