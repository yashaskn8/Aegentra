"""S0 scope requires distinct customer and security custodians."""
from dataclasses import replace
import hashlib

import rfc8785
from aegentra.fixed_delivery import FixedStaticProfile
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from aegentra.enrollment_contract import (
    EnrolledOwner, EnrollmentRejected, OwnerEndorsement,
    ProtectedOriginContract, SignedOwnerEndorsement,
    owner_message, verify_frozen_scope,
)


def fixture():
    now = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)
    profile = FixedStaticProfile(
        host="static.example.test", script_sha256="1" * 64,
        script_length=100,
    )
    html = profile.generated_html()
    headers_sha = hashlib.sha256(
        b"aegentra.delivery.profile.v1\x00"
        + rfc8785.dumps(profile.headers(path=profile.entry_path, content=html))
    ).hexdigest()
    contract = ProtectedOriginContract(
        kind="aegentra.enrollment.protected-origin.v1",
        org_id=uuid4(), target_id=uuid4(), incarnation=uuid4(),
        destination_host="static.example.test",
        html_path="/index.html", classic_js_path=profile.script_path,
        script_sha256=profile.script_sha256, script_length=profile.script_length,
        html_max_bytes=524288, js_max_bytes=1048576,
        origin_bucket="pinned-static-origin", origin_prefix="published/enrolled/",
        workload_account="123456789012", analysis_account="123456789013",
        security_account="123456789014", aws_region="us-east-1",
        residency_policy_sha256="a" * 64, incident_policy_sha256="b" * 64,
        fixture_oracle_sha256="c" * 64, delivery_profile_sha256=headers_sha,
        outage_behavior="DENY_PROTECTED_READS",
        release_mode="SHADOW_PENDING_INDEPENDENT_QUALIFICATION",
        max_admission_milliseconds=2000,
        signed_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(days=7),
    )
    signatures = []
    enrolled = {}
    for index, role in enumerate(
        ("CUSTOMER_ORIGIN_OWNER", "SECURITY_CUSTODIAN"), start=1,
    ):
        private = ec.generate_private_key(ec.SECP256R1())
        person = uuid4()
        key_id = f"enrolled-custody-key-{index}"
        enrollment = EnrolledOwner(
            key_id=key_id, person_id=person,
            custody_group=f"distinct-custodian-{index}",
            public_der=private.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            independently_enrolled=True, active=True,
        )
        body = OwnerEndorsement(
            kind="aegentra.enrollment.owner-approval.v1",
            role=role, contract_sha256=contract.digest(),
            person_id=person, key_id=key_id,
            custody_group=enrollment.custody_group,
            expires_at=now + timedelta(days=1),
        )
        signatures.append(SignedOwnerEndorsement(
            body, private.sign(owner_message(body), ec.ECDSA(hashes.SHA256())),
        ))
        enrolled[key_id] = enrollment
    return contract, tuple(signatures), enrolled, now


def check(contract, signatures, enrolled, now):
    return verify_frozen_scope(
        contract=contract, signatures=signatures,
        enrolled_owners=enrolled, now=now,
    )


def test_both_independent_owners_only_approve_shadow_scope():
    contract, signatures, enrolled, now = fixture()
    result = check(contract, signatures, enrolled, now)
    assert result.contract_sha256 == contract.digest()
    assert result.status == "SHADOW_ONLY_INDEPENDENT_QUALIFICATION_REQUIRED"
    assert check(contract, signatures[::-1], enrolled, now) == result


@pytest.mark.parametrize("mode", [
    "wrong_key", "self", "same_group", "changed_contract", "signature",
    "expired", "revoked", "wrong_role", "missing_owner",
])
def test_invalid_owner_or_stale_scope_is_rejected(mode):
    contract, signed, enrolled, now = fixture()
    signed = list(signed)
    if mode == "wrong_key":
        private = ec.generate_private_key(ec.SECP256R1())
        old = enrolled[signed[0].body.key_id]
        enrolled[old.key_id] = replace(
            old, public_der=private.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    elif mode == "self":
        signed[1] = SignedOwnerEndorsement(
            signed[1].body.model_copy(
                update={"person_id": signed[0].body.person_id}
            ),
            signed[1].signature_der,
        )
    elif mode == "same_group":
        old = enrolled[signed[1].body.key_id]
        enrolled[old.key_id] = replace(
            old, custody_group=signed[0].body.custody_group
        )
    elif mode == "changed_contract":
        contract = contract.model_copy(update={
            "delivery_profile_sha256": "0" * 64,
        })
    elif mode == "signature":
        signed[1] = SignedOwnerEndorsement(signed[1].body, b"x" * 64)
    elif mode == "expired":
        now += timedelta(days=2)
    elif mode == "revoked":
        old = enrolled[signed[1].body.key_id]
        enrolled[old.key_id] = replace(old, active=False)
    elif mode == "wrong_role":
        signed[1] = SignedOwnerEndorsement(
            signed[1].body.model_copy(
                update={"role": "CUSTOMER_ORIGIN_OWNER"}
            ),
            signed[1].signature_der,
        )
    elif mode == "missing_owner":
        signed = signed[:1]
    with pytest.raises(EnrollmentRejected):
        check(contract, tuple(signed), enrolled, now)


def test_scope_rejects_same_account_or_unqualified_web_profile():
    contract, signed, enrolled, now = fixture()
    with pytest.raises(ValueError):
        ProtectedOriginContract.model_validate({
            **contract.model_dump(mode="json"),
            "security_account": contract.workload_account,
        })
    with pytest.raises(ValueError):
        ProtectedOriginContract.model_validate({
            **contract.model_dump(mode="json"),
            "classic_js_path": "/chunks/runtime.mjs",
        })
    with pytest.raises(ValueError):
        ProtectedOriginContract.model_validate({
            **contract.model_dump(mode="json"),
            "release_mode": "ENFORCED",
        })
