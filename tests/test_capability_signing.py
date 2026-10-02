import pytest

from shared.capability_grant import issue_capability_grant
from shared.capability_policy import ActionIntent, CapabilityPolicy
from shared.capability_signing import CapabilitySignatureError, CapabilitySigner, SignedCapabilityGrant


def _intent(**overrides):
    values = {
        "role": "developer",
        "action": "delete",
        "target": "workspace/obsolete.txt",
        "resource": "staging_filesystem",
        "destination": "staging",
        "data_scope": "source_code",
        "irreversible": True,
        "requires_filesystem": True,
        "read_only": False,
        "evidence_required": True,
        "parameters": {"outcome_contract": {"type": "state_match", "verifier": "filesystem_independent_v1", "expected_state": "ABSENT"}},
    }
    values.update(overrides)
    return ActionIntent(**values)


def _signed(signer=None, **overrides):
    signer = signer or CapabilitySigner.generate()
    grant = issue_capability_grant(
        "task-1", _intent(**overrides), CapabilityPolicy.VERSION,
        ["evidence-1"], "staging",
    )
    return signer, signer.sign(grant)


def test_signature_round_trip_and_canonical_artifact():
    signer, signed = _signed()
    payload = signed.to_dict()
    restored = SignedCapabilityGrant.from_dict(payload)
    verified = signer.verify(restored)
    assert verified.grant_id == signed.grant.grant_id
    assert restored.key_id == signer.key_id
    assert restored.signature


def test_tampered_target_in_grant_breaks_signature():
    signer, signed = _signed()
    payload = signed.to_dict()
    payload["grant"]["authorized_target"] = "production"
    restored = SignedCapabilityGrant.from_dict(payload)
    with pytest.raises(CapabilitySignatureError, match="signature_invalid"):
        signer.verify(restored)


def test_tampered_signature_is_rejected():
    signer, signed = _signed()
    payload = signed.to_dict()
    payload["signature"] = "invalid"
    restored = SignedCapabilityGrant.from_dict(payload)
    with pytest.raises(CapabilitySignatureError, match="signature_invalid"):
        signer.verify(restored)


def test_wrong_signer_is_rejected():
    signer, signed = _signed()
    other = CapabilitySigner.generate()
    with pytest.raises(CapabilitySignatureError, match="signer_key_id_mismatch"):
        other.verify(signed)


def test_signature_binds_evidence_and_policy():
    signer, signed = _signed()
    payload = signed.to_dict()
    payload["grant"]["evidence_ids"] = ["attacker-evidence"]
    with pytest.raises(CapabilitySignatureError, match="evidence_hash_mismatch"):
        SignedCapabilityGrant.from_dict(payload)
