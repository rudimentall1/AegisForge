import sqlite3
import pytest

from shared.agent_authority import AgentAuthorityError, AgentAuthorityRegistry
from shared.authority_state import AuthorityState
from shared.capability_policy import ActionIntent
from shared.trust_evaluation import TrustDecision


def decision(status, proof_id):
    return TrustDecision(status=status, reason="test", proof_id=proof_id, verifier="test")


def intent(action="inspect_code", **overrides):
    values = {
        "role": "developer",
        "action": action,
        "read_only": True,
    }
    values.update(overrides)
    return ActionIntent(**values)


def test_register_creates_single_authority_context():
    registry = AgentAuthorityRegistry(sqlite3.connect(":memory:"))
    authority = registry.register("agent-1")
    assert authority.state == AuthorityState.PROBATION
    assert authority.policy_version == "capability-policy-v1"
    assert authority.authority_epoch == 1
    assert registry.register("agent-1") == authority


def test_unregistered_agent_fails_closed():
    registry = AgentAuthorityRegistry(sqlite3.connect(":memory:"))
    with pytest.raises(AgentAuthorityError, match="agent_not_registered"):
        registry.get("missing")


def test_evaluate_uses_persisted_dynamic_authority():
    registry = AgentAuthorityRegistry(sqlite3.connect(":memory:"))
    registry.register("agent-1")
    result = registry.evaluate("agent-1", intent())
    assert result.decision.value == "ALLOW"

    blocked = registry.evaluate("agent-1", intent("deploy", read_only=False))
    assert blocked.decision.value == "BLOCK"


def test_trust_updates_registry_and_persists():
    db = sqlite3.connect(":memory:")
    registry = AgentAuthorityRegistry(db)
    registry.register("agent-1")
    authority, transition = registry.record_trust("agent-1", decision("TRUSTED", "proof-1"))
    assert authority.state == AuthorityState.STANDARD
    assert authority.trusted_outcomes == 1
    assert transition.new_state == AuthorityState.STANDARD

    restored = AgentAuthorityRegistry(db).get("agent-1")
    assert restored.state == AuthorityState.STANDARD
    assert restored.last_proof_id == "proof-1"


def test_governance_elevated_requires_evidence_and_is_persistent():
    registry = AgentAuthorityRegistry(sqlite3.connect(":memory:"))
    registry.register("agent-1")
    for i in range(3):
        registry.record_trust("agent-1", decision("TRUSTED", f"proof-{i}"))
    authority, transition = registry.governance_promote_elevated("agent-1", "approved")
    assert authority.state == AuthorityState.ELEVATED
    assert transition.new_state == AuthorityState.ELEVATED


def test_failed_outcome_prevents_governance_elevation():
    registry = AgentAuthorityRegistry(sqlite3.connect(":memory:"))
    registry.register("agent-1")
    for i in range(3):
        registry.record_trust("agent-1", decision("TRUSTED", f"proof-{i}"))
    registry.record_trust("agent-1", decision("UNTRUSTED", "bad"))
    with pytest.raises(Exception, match="elevated_conditions_not_met"):
        registry.governance_promote_elevated("agent-1", "approved")


def test_suspend_and_governance_reset_increment_epoch():
    registry = AgentAuthorityRegistry(sqlite3.connect(":memory:"))
    registry.register("agent-1")
    registry.suspend("agent-1", "critical")
    assert registry.get("agent-1").state == AuthorityState.SUSPENDED
    authority, transition = registry.governance_reset("agent-1", "incident_review")
    assert authority.state == AuthorityState.PROBATION
    assert authority.authority_epoch == 3
    assert transition.new_state == AuthorityState.PROBATION


def test_policy_rotation_increments_epoch():
    registry = AgentAuthorityRegistry(sqlite3.connect(":memory:"))
    registry.register("agent-1")
    authority = registry.rotate_policy("agent-1", "capability-policy-v2")
    assert authority.policy_version == "capability-policy-v2"
    assert authority.authority_epoch == 2

