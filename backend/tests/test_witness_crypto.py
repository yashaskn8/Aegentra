from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from aegentra.witness_crypto import (
    WitnessBody, WitnessRejected, WitnessSelection,
    signed_certificate_bytes, verify_witness_certificate, witness_message,
)


def fixture():
    now = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)
    incarnation, org, target = uuid4(), uuid4(), uuid4()
    body = WitnessBody(
        kind="aegentra.security.witness.v1",
        audience="aegentra-release-publication",
        incarnation=incarnation, org_id=org, target_id=target,
        attempt_sequence=5, prior_published_revision=2,
        predecessor_witness_sha256="0" * 64, subject_sha256="1" * 64,
        approval_set_sha256="2" * 64, staging_sha256="3" * 64,
        content_sha256="4" * 64, delivery_profile_sha256="5" * 64, fixed_bundle_sha256="9" * 64,
        security_root_generation=7,
        selection_deadline=now + timedelta(seconds=40), issued_at=now,
    )
    selected = WitnessSelection(
        org_id=org, target_id=target, attempt_sequence=5,
        prior_published_revision=2, subject_sha256="1" * 64,
        approval_set_sha256="2" * 64, staging_sha256="3" * 64,
        content_sha256="4" * 64, delivery_profile_sha256="5" * 64, fixed_bundle_sha256="9" * 64,
        predecessor_witness_sha256="0" * 64, selected_at=now,
        expires_at=body.selection_deadline,
    )
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    signature = key.sign(witness_message(body), ec.ECDSA(hashes.SHA256()))
    return body, selected, incarnation, key, public, signature, now


def check(body, selected, incarnation, public, signature, now, stopped=False):
    return verify_witness_certificate(
        body=body, selection=selected, incarnation=incarnation,
        pinned_public_key_der=public, signature=signature,
        root_generation=7, no_external_veto=not stopped, now=now,
    )


def test_signed_witness_certificate_binds_selection_and_key():
    body, selected, incarnation, key, public, sig, now = fixture()
    assert check(body, selected, incarnation, public, sig, now)
    assert len(signed_certificate_bytes(body, sig)) > 100


@pytest.mark.parametrize("change", [
    "wrong_selection", "wrong_key", "stopped", "wrong_root", "expired",
    "wrong_subject", "wrong_bundle", "signature_replay", "wrong_audience",
])
def test_certificate_cannot_authorize_invalid_input(change):
    body, selected, incarnation, key, public, sig, now = fixture()
    stopped = False
    if change == "wrong_selection":
        selected = selected.__class__(**{
            **selected.__dict__, "attempt_sequence": selected.attempt_sequence + 1
        })
    elif change == "wrong_key":
        public = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    elif change == "stopped":
        stopped = True
    elif change == "wrong_root":
        incarnation = uuid4()
    elif change == "expired":
        now += timedelta(minutes=1)
    elif change == "wrong_subject":
        body = body.model_copy(update={"subject_sha256": "9" * 64})
    elif change == "wrong_bundle":
        body = body.model_copy(update={"fixed_bundle_sha256": "a" * 64})
    elif change == "signature_replay":
        sig = key.sign(b"aegentra.release.grant.v1\x00" + body.canonical(),
                       ec.ECDSA(hashes.SHA256()))
    else:
        body = body.model_copy(update={"audience": "wrong-audience"})
    with pytest.raises((WitnessRejected, ValueError)):
        check(body, selected, incarnation, public, sig, now, stopped)
