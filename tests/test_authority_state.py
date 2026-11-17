import sqlite3
import pytest

from shared.authority_state import (
    AuthorityState,
    AuthorityStateError,
    AuthorityStateMachine,
    AuthorityStateStore,
)
from shared.trust_evaluation import TrustDecision


def decision(status, proof_id="proof-1", reason="test"):
    return TrustDecision(
        status=status,
        reason=reason,
        proof_id=proof_id,
        verifier="test-verifier",
    )


def test_new_agent_starts_in_probation():
    machine = AuthorityStateMachine("agent-1")

    assert machine.state == AuthorityState.PROBATION


def test_trusted_outcome_promotes_to_standard():
    machine = AuthorityStateMachine("agent-1")

    transition = machine.apply_trust(
        decision("TRUSTED", "proof-1")
    )

    assert transition.new_state == AuthorityState.STANDARD
    assert machine.state == AuthorityState.STANDARD


def test_repeated_trusted_outcomes_do_not_auto_promote_to_elevated():
    machine = AuthorityStateMachine("agent-1")

    machine.apply_trust(decision("TRUSTED", "proof-1"))
    machine.apply_trust(decision("TRUSTED", "proof-2"))
    transition = machine.apply_trust(decision("TRUSTED", "proof-3"))

    assert transition.new_state == AuthorityState.STANDARD
    assert machine.state == AuthorityState.STANDARD


def test_governance_can_promote_to_elevated_after_evidence_conditions():
    machine = AuthorityStateMachine("agent-1")
    machine.apply_trust(decision("TRUSTED", "proof-1"))
    machine.apply_trust(decision("TRUSTED", "proof-2"))
    machine.apply_trust(decision("TRUSTED", "proof-3"))

    transition = machine.governance_promote_elevated("approved_by_governance", "proof-3")

    assert transition.new_state == AuthorityState.ELEVATED
    assert machine.state == AuthorityState.ELEVATED


def test_governance_promotion_fails_after_failed_outcome():
    machine = AuthorityStateMachine("agent-1")
    machine.apply_trust(decision("TRUSTED", "proof-1"))
    machine.apply_trust(decision("TRUSTED", "proof-2"))
    machine.apply_trust(decision("TRUSTED", "proof-3"))
    machine.apply_trust(decision("UNTRUSTED", "proof-4", "bad_outcome"))

    with pytest.raises(AuthorityStateError, match="elevated_conditions_not_met"):
        machine.governance_promote_elevated("approved_by_governance", "proof-3")


def test_untrusted_outcome_restricts_authority():
    machine = AuthorityStateMachine("agent-1")

    machine.apply_trust(decision("TRUSTED", "proof-1"))
    transition = machine.apply_trust(
        decision("UNTRUSTED", "proof-2", "bad_outcome")
    )

    assert transition.new_state == AuthorityState.LIMITED
    assert machine.state == AuthorityState.LIMITED


def test_expired_attestation_restricts_authority():
    machine = AuthorityStateMachine("agent-1")

    transition = machine.apply_trust(
        decision("EXPIRED", "proof-1", "attestation_expired")
    )

    assert transition.new_state == AuthorityState.LIMITED


def test_suspended_agent_cannot_self_restore_from_trust():
    machine = AuthorityStateMachine("agent-1")

    machine.suspend("critical_failure")
    machine.apply_trust(decision("TRUSTED", "proof-1"))

    assert machine.state == AuthorityState.SUSPENDED


def test_governance_reset_returns_to_probation():
    machine = AuthorityStateMachine("agent-1")

    machine.suspend("critical_failure")
    transition = machine.governance_reset()

    assert transition.new_state == AuthorityState.PROBATION
    assert machine.state == AuthorityState.PROBATION
    assert machine.record.trusted_outcomes == 0
    assert machine.record.failed_outcomes == 0


def test_missing_agent_id_fails_closed():
    try:
        AuthorityStateMachine("")
    except AuthorityStateError as exc:
        assert str(exc) == "agent_id_required"
    else:
        raise AssertionError("expected AuthorityStateError")


def test_authority_state_store_persists_state_and_history():
    db = sqlite3.connect(":memory:")
    store = AuthorityStateStore(db)
    machine = store.load("agent-persist")
    machine.apply_trust(decision("TRUSTED", "proof-a"))
    machine.apply_trust(decision("TRUSTED", "proof-b"))
    store.save(machine)
    restored = store.load("agent-persist")
    assert restored.state == AuthorityState.STANDARD
    assert restored.record.trusted_outcomes == 2
    assert restored.record.last_proof_id == "proof-b"
    assert len(restored.history) == 2
    assert restored.history[-1].proof_id == "proof-b"


def test_authority_state_store_rejects_corrupt_state():
    db = sqlite3.connect(":memory:")
    store = AuthorityStateStore(db)
    db.execute("INSERT INTO authority_state VALUES (?, ?, ?, ?, ?, ?)",
               ("bad-agent", "NOT_A_STATE", 0, 0, "", "authority-state-v1"))
    db.commit()
    with pytest.raises(AuthorityStateError, match="invalid_persisted_state"):
        store.load("bad-agent")
