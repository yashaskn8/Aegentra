"""Independent emergency STOP: no workload DB, no resume, no false ACK."""
from datetime import datetime, timezone
from uuid import uuid4
import hashlib
import io

import pytest
import rfc8785
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from aegentra.gateway_signatures import AdmissionDenied, verify_veto
from aegentra.security_veto import (
    SecurityAccountVeto, SecurityRootError, SecurityRootState,
    StopUnknown, KmsVetoSigner,
)


class FakeSTS:
    account = "123456789012"

    def get_caller_identity(self):
        return {"Account": self.account}


class FakeS3:
    def __init__(self, initial):
        self.objects = {}
        self.calls = []
        self.fail_pointer_update = False
        self.write("security-root/v1/" + initial.org_id.hex + "/current",
                   rfc8785.dumps(initial.model_dump(mode="json")))

    def write(self, key, body):
        self.objects[key] = bytes(body)

    def get_object(self, *, Bucket, Key):
        data = self.objects[Key]
        return {
            "Body": io.BytesIO(data), "ContentLength": len(data),
            "VersionId": "object-version-id",
            "ETag": '"etag-' + hashlib.sha256(data).hexdigest() + '"',
        }

    def put_object(self, **kwargs):
        self.calls.append(kwargs)
        key = kwargs["Key"]
        if kwargs.get("IfNoneMatch") == "*" and key in self.objects:
            raise ValueError("S3 PreconditionFailed")
        if "IfMatch" in kwargs:
            if self.fail_pointer_update:
                raise ValueError("S3 conditional root update failed")
            if key not in self.objects:
                raise ValueError("missing current pointer")
            prior = self.get_object(Bucket=kwargs["Bucket"], Key=key)["ETag"]
            if kwargs["IfMatch"] != prior:
                raise ValueError("stale CAS ETag")
        self.write(key, kwargs["Body"])
        return {"VersionId": "new-version-id"}


def fixture(minimum_veto=0):
    now = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)
    org, inc = uuid4(), uuid4()
    root = SecurityRootState(
        kind="aegentra.security.root-state.v1",
        org_id=org, incarnation=inc, root_generation=4,
        veto_generation=8, state="CLEAR",
        predecessor_sha256="0" * 64,
        incident_id=uuid4(), written_at=now,
    )
    s3, sts = FakeS3(root), FakeSTS()
    service = SecurityAccountVeto(
        s3=s3, sts=sts, bucket="security-account-root",
        expected_account="123456789012", org_id=org,
        pinned_incarnation=inc, minimum_root_generation=4,
        minimum_veto_generation=minimum_veto,
    )
    return now, service, s3, sts


def test_emergency_stop_is_persisted_but_never_claims_full_containment():
    now, service, s3, sts = fixture()
    incident = uuid4()
    result = service.emergency_stop(incident_id=incident, now=now)
    assert result.status == "VETO_RECORDED_PENDING_ACK"
    assert result.veto_generation == 9
    assert result.record_version_id == "new-version-id"
    assert s3.calls[0]["IfNoneMatch"] == "*"
    assert s3.calls[1]["IfMatch"].startswith('"etag-')
    assert service.current().body.state == "STOP"
    assert service.current().body.predecessor_sha256 != "0" * 64
    assert service.emergency_stop(incident_id=incident, now=now).veto_generation == 9
    assert len(s3.calls) == 2


def test_independent_veto_signature_blocks_gateway_after_stop():
    now, service, s3, _ = fixture()
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    class FakeKMS:
        def sign(self, **args):
            return {"Signature": key.sign(args["Message"], ec.ECDSA(hashes.SHA256()))}

    signer = KmsVetoSigner(kms=FakeKMS(), key_id="security-key",
                           pinned_public_der=public)
    nonce = "A" * 43
    clear = signer.sign(service.fresh_snapshot(nonce=nonce, now=now))
    verify_veto(
        clear, pinned_key_der=public, nonce=nonce,
        org_id=service.org_id, incarnation=service.incarnation,
        minimum_root_generation=4, now=now,
    )
    service.emergency_stop(incident_id=uuid4(), now=now)
    stopped = signer.sign(service.fresh_snapshot(nonce=nonce, now=now))
    with pytest.raises(AdmissionDenied, match="veto"):
        verify_veto(
            stopped, pinned_key_der=public, nonce=nonce,
            org_id=service.org_id, incarnation=service.incarnation,
            minimum_root_generation=4, now=now,
        )
    with pytest.raises(AdmissionDenied):
        verify_veto(
            clear, pinned_key_der=public, nonce="B" * 43,
            org_id=service.org_id, incarnation=service.incarnation,
            minimum_root_generation=4, now=now,
        )


@pytest.mark.parametrize("failure", [
    "account", "wrong_incarnation", "below_floor", "truncated",
    "invalid_bytes", "unversioned",
])
def test_unavailable_or_rolled_back_root_blocks_read(failure):
    now, service, s3, sts = fixture(minimum_veto=8)
    if failure == "account":
        sts.account = "000000000000"
    elif failure in {"wrong_incarnation", "below_floor"}:
        state = service.current().body
        if failure == "wrong_incarnation":
            state = state.model_copy(update={"incarnation": uuid4()})
        else:
            state = state.model_copy(update={"veto_generation": 7})
        s3.write(service.current_key, rfc8785.dumps(state.model_dump(mode="json")))
    elif failure == "truncated":
        old = s3.get_object
        def bad(*args, **kwargs):
            result = old(*args, **kwargs)
            result["ContentLength"] += 1
            return result
        s3.get_object = bad
    elif failure == "invalid_bytes":
        s3.write(service.current_key, b'{"state":"CLEAR","state":"STOP"}')
    else:
        old = s3.get_object
        def bad(*args, **kwargs):
            result = old(*args, **kwargs)
            result["VersionId"] = "null"
            return result
        s3.get_object = bad
    with pytest.raises(SecurityRootError):
        service.current()


def test_cas_race_never_reports_stop_success():
    now, service, s3, sts = fixture()
    s3.fail_pointer_update = True
    with pytest.raises(StopUnknown, match="containment unknown"):
        service.emergency_stop(incident_id=uuid4(), now=now)
    assert service.current().body.state == "CLEAR"
    assert any("/stops/" in c["Key"] for c in s3.calls)


def test_cannot_send_unenrolled_veto_signatures():
    now, service, s3, sts = fixture()
    with pytest.raises(ValueError):
        service.fresh_snapshot(nonce="not-a-nonce", now=now)
    with pytest.raises(SecurityRootError):
        service.emergency_stop(incident_id=uuid4(), now=datetime(2026, 11, 20))
