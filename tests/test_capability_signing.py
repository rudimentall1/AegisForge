import pytest
from types import SimpleNamespace

from shared.capability_grant import issue_capability_grant as _issue_capability_grant
from shared.authority_state import AuthorityState
from shared.capability_policy import ActionIntent, CapabilityPolicy
from shared.capability_signing import CapabilitySignatureError, CapabilitySigner, SignedCapabilityGrant
from shared.agent_identity_signing import AgentIdentitySigner


def issue_capability_grant(*args, **kwargs):
    state = kwargs.setdefault("authority_state", AuthorityState.STANDARD)
    kwargs.setdefault("authority_context", SimpleNamespace(
        agent_id="test-agent",
        authority_epoch=1,
        state=state,
        policy_version=kwargs.get("policy_version", args[2] if len(args) > 2 else "policy-v1"),
    ))
    return _issue_capability_grant(*args, **kwargs)


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
    agent = AgentIdentitySigner.generate("test-agent", "developer").sign_identity()
    return signer, signer.sign(grant, agent)


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

def test_signed_grant_binds_cryptographic_agent_identity():
    from shared.agent_identity_signing import AgentIdentitySigner
    signer = CapabilitySigner.generate()
    agent = AgentIdentitySigner.generate("agent-1", "validator").sign_identity()
    grant = issue_capability_grant(
        "task-1", _intent(), CapabilityPolicy.VERSION, ["evidence-1"], "staging",
    )
    grant = grant.__class__(**{**grant.__dict__, "agent_id": "agent-1"})
    signed = signer.sign(grant, agent)
    assert signer.verify(signed).agent_id == "agent-1"
    assert signed.agent_identity.identity.agent_id == "agent-1"


def test_signed_grant_rejects_agent_identity_mismatch():
    from shared.agent_identity_signing import AgentIdentitySigner
    signer = CapabilitySigner.generate()
    agent = AgentIdentitySigner.generate("other-agent", "validator").sign_identity()
    grant = issue_capability_grant(
        "task-1", _intent(), CapabilityPolicy.VERSION, ["evidence-1"], "staging",
    )
    grant = grant.__class__(**{**grant.__dict__, "agent_id": "agent-1"})
    with pytest.raises(CapabilitySignatureError, match="agent_identity_mismatch"):
        signer.sign(grant, agent)
