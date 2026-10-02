from datetime import datetime, timedelta, timezone

import pytest

from shared.action_intent import ActionIntent
from shared.agent_identity_signing import AgentIdentitySigner
from shared.signed_action_intent import (
    ActionIntentSigner,
    SignedActionIntent,
    SignedActionIntentError,
)


def make_intent(agent_id="agent-1"):
    return ActionIntent(
        role="validator",
        action="validate",
        agent_id=agent_id,
        target="validation-target",
        resource="research_results",
        destination="internal",
        data_scope="validation_evidence",
        read_only=True,
        parameters={"outcome_contract": {"version": "outcome-contract-v1", "claims": ["validation"]}},
    )


def test_signed_action_intent_round_trip_and_offline_verification():
    signer = AgentIdentitySigner.generate("agent-1", "validator")
    signed = ActionIntentSigner(signer).sign(make_intent())

    assert signed.verify()
    restored = SignedActionIntent.from_dict(signed.to_dict())
    assert restored.verify()
    assert restored.intent_hash == signed.intent_hash


def test_signed_action_intent_rejects_identity_mismatch():
    signer = AgentIdentitySigner.generate("agent-1", "validator")
    with pytest.raises(SignedActionIntentError, match="agent_identity_mismatch"):
        ActionIntentSigner(signer).sign(make_intent("other-agent"))


def test_signed_action_intent_rejects_tampered_intent():
    signer = AgentIdentitySigner.generate("agent-1", "validator")
    signed = ActionIntentSigner(signer).sign(make_intent())
    payload = signed.to_dict()
    payload["intent"]["target"] = "attacker-target"
    tampered = SignedActionIntent.from_dict(payload)

    with pytest.raises(SignedActionIntentError, match="intent_hash_mismatch"):
        tampered.verify()


def test_signed_action_intent_rejects_tampered_signature():
    signer = AgentIdentitySigner.generate("agent-1", "validator")
    signed = ActionIntentSigner(signer).sign(make_intent())
    payload = signed.to_dict()
    payload["signature"] = "invalid"
    tampered = SignedActionIntent.from_dict(payload)

    with pytest.raises(SignedActionIntentError, match="signature_invalid"):
        tampered.verify()


def test_signed_action_intent_rejects_expired_artifact():
    signer = AgentIdentitySigner.generate("agent-1", "validator")
    signed = ActionIntentSigner(signer).sign(make_intent(), ttl_seconds=1)
    future = datetime.now(timezone.utc) + timedelta(seconds=5)

    with pytest.raises(SignedActionIntentError, match="intent_expired"):
        signed.verify(now=future)
