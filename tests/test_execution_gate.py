import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from types import SimpleNamespace

from shared.capability_grant import issue_capability_grant as _issue_capability_grant
from shared.authority_state import AuthorityState
from shared.capability_policy import ActionIntent, CapabilityPolicy
from shared.capability_signing import CapabilitySigner
from shared.execution_gate import ExecutionGate, ExecutionGateError
from shared.agent_authority import AgentAuthorityRegistry
from shared.trust_evaluation import TrustDecision


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
        "action": "deploy",
        "target": "staging",
        "resource": "service",
        "destination": "staging",
        "data_scope": "artifact",
        "read_only": False,
    }
    values.update(overrides)
    return ActionIntent(**values)


def _grant(intent=None, signer=None, **kwargs):
    intent = intent or _intent()
    signer = signer or CapabilitySigner.generate()
    grant = issue_capability_grant(
        "task-1",
        intent,
        CapabilityPolicy.VERSION,
        evidence_ids=["ev-1"],
        authorized_scope=intent.destination or intent.resource,
        **kwargs,
    )
    return signer, signer.sign(grant)


def _db():
    return sqlite3.connect(":memory:")


def test_gate_requires_grant():
    gate = ExecutionGate(_db())
    with pytest.raises(ExecutionGateError, match="grant_required"):
        gate.execute(None, _intent(), lambda: "executed", ["ev-1"])


def test_gate_rejects_policy_drift():
    signer, grant = _grant()
    gate = ExecutionGate(_db(), signer=signer)
    gate.policy.VERSION = "changed"
    with pytest.raises(ExecutionGateError, match="policy_version_mismatch"):
        gate.execute(grant, _intent(), lambda: "executed", ["ev-1"])


def test_gate_enforces_scope():
    intent = _intent()
    signer, signed = _grant(intent)
    grant = signer.sign(replace(signed.grant, authorized_scope="other"))
    gate = ExecutionGate(_db(), signer=signer)
    with pytest.raises(ExecutionGateError, match="authorized_scope_mismatch"):
        gate.execute(grant, intent, lambda: "executed", ["ev-1"])


def test_gate_executes_once_and_returns_receipt():
    signer, grant = _grant()
    gate = ExecutionGate(_db(), signer=signer)
    calls = []
    receipt = gate.execute(
        grant,
        _intent(),
        lambda: calls.append("ran") or {"ok": True},
        ["ev-1"],
    )
    assert receipt.status == "EXECUTED"
    assert receipt.grant_id == grant.grant.grant_id
    assert receipt.intent_hash == grant.grant.intent_hash
    assert receipt.result == {"ok": True}
    assert calls == ["ran"]

    with pytest.raises(ExecutionGateError, match="grant_replayed"):
        gate.execute(grant, _intent(), lambda: calls.append("again"), ["ev-1"])
    assert calls == ["ran"]


def test_gate_rejects_expired_grant():
    signer, grant = _grant(ttl_seconds=1)
    gate = ExecutionGate(_db(), signer=signer)
    future = datetime.now(timezone.utc) + timedelta(seconds=2)
    with pytest.raises(ExecutionGateError, match="grant_expired"):
        gate.execute(grant, _intent(), lambda: "executed", ["ev-1"], now=future)


def test_failed_executor_still_produces_failure_receipt_and_consumes_grant():
    signer, grant = _grant()
    gate = ExecutionGate(_db(), signer=signer)
    receipt = gate.execute(
        grant,
        _intent(),
        lambda: (_ for _ in ()).throw(RuntimeError("boom")),
        ["ev-1"],
    )
    assert receipt.status == "FAILED"
    assert "RuntimeError: boom" in receipt.error

    with pytest.raises(ExecutionGateError, match="grant_replayed"):
        gate.execute(grant, _intent(), lambda: "again", ["ev-1"])


def test_gate_honors_persistent_grant_revocation_before_side_effect():
    db = _db()
    signer, grant = _grant()
    gate = ExecutionGate(db, signer=signer)
    # Registration happens at the gate boundary, before execution.
    gate.authorize(grant, _intent(), ["ev-1"])
    from shared.capability_grant_store import CapabilityGrantStore

    store = CapabilityGrantStore(db)
    assert store.status(grant.grant.grant_id) == "ACTIVE"
    store.revoke(grant.grant.grant_id, "security_review")

    calls = []
    with pytest.raises(ExecutionGateError, match="grant_revoked"):
        gate.execute(
            grant,
            _intent(),
            lambda: calls.append("must-not-run"),
            ["ev-1"],
        )
    assert calls == []


def _registered_authority(db, agent_id="agent-1"):
    registry = AgentAuthorityRegistry(db)
    registry.register(agent_id)
    registry.record_trust(
        agent_id,
        TrustDecision("TRUSTED", "test", "proof-1", "test-verifier"),
    )
    return registry, registry.get(agent_id)


def test_gate_rejects_stale_authority_epoch():
    db = _db()
    registry, authority = _registered_authority(db)
    intent = _intent()
    signer = CapabilitySigner.generate()
    grant = signer.sign(issue_capability_grant(
        "task-epoch",
        intent,
        CapabilityPolicy.VERSION,
        evidence_ids=["ev-1"],
        authorized_scope="staging",
        authority_state=authority.state,
        authority_context=authority,
    ))
    registry.governance_reset("agent-1", "security_reset")
    gate = ExecutionGate(db, signer=signer, authority_registry=registry)

    with pytest.raises(ExecutionGateError, match="authority_epoch_mismatch"):
        gate.execute(grant, intent, lambda: "must-not-run", ["ev-1"])


def test_gate_rejects_authority_state_drift():
    db = _db()
    registry, authority = _registered_authority(db)
    intent = _intent()
    signer = CapabilitySigner.generate()
    grant = signer.sign(issue_capability_grant(
        "task-state",
        intent,
        CapabilityPolicy.VERSION,
        evidence_ids=["ev-1"],
        authorized_scope="staging",
        authority_state=authority.state,
        authority_context=authority,
    ))
    registry.suspend("agent-1", "incident")
    gate = ExecutionGate(db, signer=signer, authority_registry=registry)

    with pytest.raises(ExecutionGateError, match="authority_epoch_mismatch"):
        gate.execute(grant, intent, lambda: "must-not-run", ["ev-1"])


def test_current_authority_context_allows_execution():
    db = _db()
    registry, authority = _registered_authority(db)
    intent = _intent()
    signer = CapabilitySigner.generate()
    grant = signer.sign(issue_capability_grant(
        "task-current",
        intent,
        CapabilityPolicy.VERSION,
        evidence_ids=["ev-1"],
        authorized_scope="staging",
        authority_state=authority.state,
        authority_context=authority,
    ))
    gate = ExecutionGate(db, signer=signer, authority_registry=registry)

    receipt = gate.execute(grant, intent, lambda: "executed", ["ev-1"])
    assert receipt.status == "EXECUTED"
