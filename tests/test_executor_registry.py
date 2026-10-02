import sqlite3

import pytest
from types import SimpleNamespace

from shared.capability_grant import issue_capability_grant as _issue_capability_grant
from shared.authority_state import AuthorityState
from shared.capability_policy import ActionIntent, CapabilityPolicy
from shared.capability_signing import CapabilitySigner
from shared.evidence_ledger import EvidenceLedger
from shared.execution_gate import ExecutionGate
from shared.agent_authority import AgentAuthorityRegistry
from shared.trust_evaluation import TrustDecision
from shared.executor_registry import ExecutorRegistry, ExecutorRegistryError


def issue_capability_grant(*args, **kwargs):
    state = kwargs.setdefault("authority_state", AuthorityState.STANDARD)
    kwargs.setdefault("authority_context", SimpleNamespace(
        agent_id="test-agent",
        authority_epoch=2,
        state=state,
        policy_version=kwargs.get("policy_version", args[2] if len(args) > 2 else "policy-v1"),
    ))
    return _issue_capability_grant(*args, **kwargs)


def _intent(action="deploy", resource="staging"):
    return ActionIntent(
        role="developer",
        action=action,
        target=resource,
        resource=resource,
        destination=resource,
        data_scope="source_code",
        read_only=False,
        evidence_required=True,
        parameters=({"outcome_contract": {"type": "artifact_exists", "verifier": "artifact_independent_v1", "path": resource, "expected_exists": True}} if action == "publish" else {}),
    )


def _grant(intent, signer):
    grant = issue_capability_grant(
        task_id="task-1",
        intent=intent,
        policy_version=CapabilityPolicy.VERSION,
        evidence_ids=["e1", "e2"],
        authorized_scope=intent.destination,
    )
    return signer.sign(grant)


def _runtime():
    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    signer = CapabilitySigner.generate()
    authority = AgentAuthorityRegistry(db)
    authority.register("test-agent")
    authority.record_trust("test-agent", TrustDecision("TRUSTED", "test", "proof-executor", "test"))
    gate = ExecutionGate(db=db, signer=signer, authority_registry=authority)
    return db, ledger, ExecutorRegistry(gate, evidence_ledger=ledger), signer


def test_successful_execution_creates_receipt_and_ledger_evidence():
    _, ledger, registry, signer = _runtime()
    intent = _intent()
    grant = _grant(intent, signer)
    calls = []
    registry.register("staging_deploy", "deploy", "staging", lambda current: calls.append(current.target) or {"ok": True})

    result = registry.execute(grant, intent, evidence_ids=["e1", "e2"])

    assert calls == ["staging"]
    assert result["receipt"].status == "EXECUTED"
    assert result["evidence"]["receipt_id"] == result["receipt"].receipt_id
    assert ledger.evidence_quality(result["evidence"]["evidence_id"])["kind"] == "execution_receipt"


def test_missing_grant_blocks_before_handler():
    _, _, registry, signer = _runtime()
    intent = _intent()
    calls = []
    registry.register("staging_deploy", "deploy", "staging", lambda current: calls.append(True))

    with pytest.raises(ExecutorRegistryError, match="grant_required"):
        registry.execute(None, intent, evidence_ids=["e1", "e2"])

    assert calls == []


def test_wrong_target_is_blocked_before_handler():
    _, _, registry, signer = _runtime()
    intent = _intent()
    grant = _grant(intent, signer)
    calls = []
    registry.register("staging_deploy", "deploy", "staging", lambda current: calls.append(True))
    tampered = ActionIntent(
        role=intent.role,
        action=intent.action,
        target="production",
        resource=intent.resource,
        destination=intent.destination,
        data_scope=intent.data_scope,
        read_only=intent.read_only,
        evidence_required=intent.evidence_required,
    )
    with pytest.raises(ExecutorRegistryError, match="intent_hash_mismatch"):
        registry.execute(grant, tampered, evidence_ids=["e1", "e2"])
    assert calls == []


def test_failed_handler_creates_failed_receipt_and_evidence():
    _, _, registry, signer = _runtime()
    intent = _intent()
    grant = _grant(intent, signer)
    registry.register("staging_deploy", "deploy", "staging", lambda current: (_ for _ in ()).throw(RuntimeError("boom")))

    result = registry.execute(grant, intent, evidence_ids=["e1", "e2"])

    assert result["receipt"].status == "FAILED"
    assert "RuntimeError: boom" in result["receipt"].error
    assert result["evidence"]["status"] == "FAILED"


def test_replay_does_not_call_handler_twice():
    _, _, registry, signer = _runtime()
    intent = _intent()
    grant = _grant(intent, signer)
    calls = []
    registry.register("staging_deploy", "deploy", "staging", lambda current: calls.append(True) or {"ok": True})

    registry.execute(grant, intent, evidence_ids=["e1", "e2"])
    with pytest.raises(ExecutorRegistryError, match="grant_replayed"):
        registry.execute(grant, intent, evidence_ids=["e1", "e2"])

    assert len(calls) == 1


def test_unknown_executor_is_blocked():
    _, _, registry, signer = _runtime()
    intent = _intent(action="publish", resource="staging")
    grant = _grant(intent, signer)

    with pytest.raises(ExecutorRegistryError, match="executor_not_registered"):
        registry.execute(grant, intent, evidence_ids=["e1", "e2"])
