from shared.authority_state import (
    AuthorityState,
    AuthorityStateError,
    AuthorityStateMachine,
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


def test_repeated_trusted_outcomes_promote_to_elevated():
    machine = AuthorityStateMachine("agent-1")

    machine.apply_trust(decision("TRUSTED", "proof-1"))
    machine.apply_trust(decision("TRUSTED", "proof-2"))
    transition = machine.apply_trust(decision("TRUSTED", "proof-3"))

    assert transition.new_state == AuthorityState.ELEVATED
    assert machine.state == AuthorityState.ELEVATED


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
