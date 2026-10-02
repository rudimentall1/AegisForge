import pytest

from shared.agent_identity import AgentIdentity
from shared.agent_identity_signing import (
    AgentIdentitySigner,
    AgentIdentitySignatureError,
    SignedAgentIdentity,
)


def test_generated_identity_is_cryptographically_verifiable():
    signer = AgentIdentitySigner.generate("agent-1", "validator")
    signed = signer.sign_identity()

    assert signed.identity.agent_id == "agent-1"
    assert signed.key_id.startswith("agent-ed25519-")
    assert AgentIdentitySigner.verify_identity(signed).to_dict() == signer.identity.to_dict()


def test_tampered_identity_is_rejected():
    signer = AgentIdentitySigner.generate("agent-1", "validator")
    payload = signer.sign_identity().to_dict()
    payload["identity"]["role"] = "worker"

    with pytest.raises((AgentIdentitySignatureError, ValueError)):
        AgentIdentitySigner.verify_identity(SignedAgentIdentity.from_dict(payload))


def test_tampered_signature_is_rejected():
    signer = AgentIdentitySigner.generate("agent-1", "validator")
    payload = signer.sign_identity().to_dict()
    payload["signature"] = payload["signature"][:-2] + "xx"

    with pytest.raises(AgentIdentitySignatureError, match="signature"):
        AgentIdentitySigner.verify_identity(SignedAgentIdentity.from_dict(payload))


def test_key_id_is_bound_to_public_key():
    signer = AgentIdentitySigner.generate("agent-1", "validator")
    payload = signer.sign_identity().to_dict()
    payload["key_id"] = "agent-ed25519-" + "0" * 16

    with pytest.raises(AgentIdentitySignatureError, match="key_id"):
        AgentIdentitySigner.verify_identity(SignedAgentIdentity.from_dict(payload))


def test_private_key_persistence(tmp_path):
    path = tmp_path / "agent.key"
    first = AgentIdentitySigner.load_or_create(str(path), "agent-1", "validator")
    second = AgentIdentitySigner.load_or_create(str(path), "agent-1", "validator")

    assert first.public_key == second.public_key
    assert first.key_id == second.key_id
    assert path.stat().st_mode & 0o777 == 0o600
    assert AgentIdentitySigner.verify_identity(second.sign_identity()).agent_id == "agent-1"
