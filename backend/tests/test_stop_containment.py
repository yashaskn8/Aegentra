"""Containment is unknown until every independent gateway ACK and drain."""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from aegentra.security_veto import SecurityRootState
from aegentra.stop_containment import (
    AuthorityFence, ContainmentRejected, GatewayStopAck,
    SignedFence, SignedGatewayAck, SignerCredential,
    assess_stop_containment, fence_message, gateway_ack_message,
)


def make_signer(identity):
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return key, SignerCredential(identity, public, independently_enrolled=True)


def fixture():
    t = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)
    org, incarnation, target = uuid4(), uuid4(), uuid4()
    root = SecurityRootState(
        kind="aegentra.security.root-state.v1",
        org_id=org, incarnation=incarnation, root_generation=3,
        veto_generation=7, state="STOP", predecessor_sha256="0" * 64,
        incident_id=uuid4(), written_at=t,
    )
    auth_key, auth_enrollment = make_signer("authority-fence-key")
    fence = AuthorityFence(
        kind="aegentra.incident.authority-fenced.v1",
        audience="aegentra-stop-containment",
        org_id=org, incarnation=incarnation, target_id=target,
        veto_generation=7, target_epoch=5, guard="STOP_SERVING",
        signer_key_id=auth_enrollment.key_id,
        fenced_at=t + timedelta(seconds=1),
        signed_at=t + timedelta(seconds=2),
    )
    signed_fence = SignedFence(
        fence, auth_key.sign(fence_message(fence), ec.ECDSA(hashes.SHA256())),
    )
    enrolled = {}
    private = {}
    acknowledgments = []
    for name in ("gateway-one", "gateway-two"):
        key, cred = make_signer(f"{name}-credential")
        private[name] = key
        enrolled[name] = cred
        ack = GatewayStopAck(
            kind="aegentra.incident.gateway-stopped.v1",
            audience="aegentra-stop-containment",
            org_id=org, incarnation=incarnation, target_id=target,
            gateway_id=name, veto_generation=7, state="STOP",
            signer_key_id=cred.key_id,
            admissions_closed_at=t + timedelta(seconds=3),
            last_write_deadline=t + timedelta(seconds=8),
            signed_at=t + timedelta(seconds=4),
        )
        acknowledgments.append(SignedGatewayAck(
            ack, key.sign(gateway_ack_message(ack), ec.ECDSA(hashes.SHA256()))
        ))
    return dict(
        root=root, target_id=target, authority_fence=signed_fence,
        authority_key=auth_enrollment, gateway_acks=tuple(acknowledgments),
        enrolled_gateways=enrolled, now=t + timedelta(seconds=12),
    ), private


def test_only_all_enrolled_gateways_after_write_drain_prove_containment():
    case, keys = fixture()
    result = assess_stop_containment(**case)
    assert result.contained is True
    assert result.phase == "CONTAINED"
    assert result.missing_gateways == ()


def test_veto_root_without_authority_fence_is_not_containment():
    case, keys = fixture()
    result = assess_stop_containment(**{
        **case, "authority_fence": None
    })
    assert result.phase == "VETO_RECORDED"
    assert not result.contained


def test_missing_ack_remains_authority_fenced():
    case, keys = fixture()
    result = assess_stop_containment(**{
        **case, "gateway_acks": case["gateway_acks"][:1]
    })
    assert result.phase == "AUTHORITY_FENCED"
    assert result.missing_gateways == ("gateway-two",)
    assert not result.contained


def test_all_acks_before_latest_write_deadline_are_still_draining():
    case, keys = fixture()
    result = assess_stop_containment(**{
        **case, "now": case["root"].written_at + timedelta(seconds=8),
    })
    assert result.phase == "GATEWAYS_ACKNOWLEDGED_DRAINING"
    assert not result.contained


def test_no_enrolled_gateway_set_never_passes_vacuously():
    case, keys = fixture()
    result = assess_stop_containment(**{
        **case, "enrolled_gateways": {}, "gateway_acks": (),
    })
    assert result.phase == "AUTHORITY_FENCED"
    assert not result.contained


def test_no_confirmed_external_stop_is_not_containment():
    case, keys = fixture()
    clear = case["root"].model_copy(update={"state": "CLEAR"})
    result = assess_stop_containment(**{**case, "root": clear})
    assert result.phase == "VETO_NOT_CONFIRMED"
    assert not result.contained


@pytest.mark.parametrize("tamper", [
    "wrong_authority_key", "wrong_authority_scope", "old_veto_generation",
    "unknown_gateway", "duplicate_ack", "wrong_gateway_key", "stale_gateway",
    "wrong_gateway_signature", "revoked_gateway",
])
def test_invalid_or_unenrolled_receipts_never_confirm_stop(tamper):
    case, keys = fixture()
    if tamper == "wrong_authority_key":
        _, foreign = make_signer("authority-fence-key")
        case["authority_key"] = foreign
    elif tamper == "wrong_authority_scope":
        signed = case["authority_fence"]
        case["authority_fence"] = SignedFence(
            signed.body.model_copy(update={"target_id": uuid4()}),
            signed.signature_der,
        )
    elif tamper == "old_veto_generation":
        signed = case["authority_fence"]
        case["authority_fence"] = SignedFence(
            signed.body.model_copy(update={"veto_generation": 6}),
            signed.signature_der,
        )
    elif tamper == "unknown_gateway":
        signed = case["gateway_acks"][0]
        case["gateway_acks"] = (
            SignedGatewayAck(
                signed.body.model_copy(update={"gateway_id": "unknown"}),
                signed.signature_der,
            ),
        )
    elif tamper == "duplicate_ack":
        case["gateway_acks"] = (
            case["gateway_acks"][0], case["gateway_acks"][0]
        )
    elif tamper == "wrong_gateway_key":
        _, foreign = make_signer("gateway-one-credential")
        case["enrolled_gateways"]["gateway-one"] = foreign
    elif tamper == "stale_gateway":
        signed = case["gateway_acks"][0]
        bad_body = signed.body.model_copy(update={"veto_generation": 6})
        bad_sig = keys["gateway-one"].sign(
            gateway_ack_message(bad_body), ec.ECDSA(hashes.SHA256()),
        )
        case["gateway_acks"] = (
            SignedGatewayAck(bad_body, bad_sig), case["gateway_acks"][1],
        )
    elif tamper == "wrong_gateway_signature":
        signed = case["gateway_acks"][0]
        case["gateway_acks"] = (
            SignedGatewayAck(signed.body, b"x" * 64),
            case["gateway_acks"][1],
        )
    elif tamper == "revoked_gateway":
        old = case["enrolled_gateways"]["gateway-one"]
        case["enrolled_gateways"]["gateway-one"] = SignerCredential(
            old.key_id, old.public_der, independently_enrolled=False
        )
    with pytest.raises(ContainmentRejected):
        assess_stop_containment(**case)


def test_future_stop_clock_is_not_accepted():
    case, keys = fixture()
    future = case["root"].model_copy(update={
        "written_at": case["now"] + timedelta(days=1)
    })
    result = assess_stop_containment(**{**case, "root": future})
    assert not result.contained
