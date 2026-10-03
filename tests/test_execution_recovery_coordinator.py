import sqlite3

import pytest

from shared.execution_attempt import ExecutionAttemptState, ExecutionAttemptStore
from shared.execution_recovery import RecoveryDecision
from shared.execution_recovery_coordinator import (
    ExecutionRecoveryCoordinator,
    ExecutionRecoveryCoordinatorError,
)
from shared.outcome_verifier_registry import OutcomeVerifierRegistry


class FakeRecoveryVerifier:
    def __init__(self, status):
        self.status = status

    def verify(self, intent, receipt):
        return {"status": "PROVEN", "verifier": "fake_recovery_v1", "outcome_id": "proof"}

    def verify_recovery(self, intent, contract):
        return {
            "status": self.status,
            "verifier": "filesystem_independent_v1",
            "outcome_id": "recovery-outcome-1",
        }


class Intent:
    action = "delete"


def _setup(status="SAFE_TO_RETRY"):
    db = sqlite3.connect(":memory:")
    attempts = ExecutionAttemptStore(db)
    attempt = attempts.create("task-1", "grant-1", "intent-1", "operation-1")
    attempt = attempts.transition(attempt.attempt_id, ExecutionAttemptState.LEASED)
    attempt = attempts.transition(attempt.attempt_id, ExecutionAttemptState.RUNNING)

    registry = OutcomeVerifierRegistry()
    registry.register(
        "fake",
        "state_match",
        "filesystem_independent_v1",
        lambda **kwargs: FakeRecoveryVerifier(status),
    )
    coordinator = ExecutionRecoveryCoordinator(db, registry)
    contract = {
        "type": "state_match",
        "verifier": "filesystem_independent_v1",
        "expected_state": "ABSENT",
    }
    return db, attempts, coordinator, attempt, contract


def test_safe_recovery_creates_next_attempt():
    db, attempts, coordinator, attempt, contract = _setup()

    next_attempt = coordinator.retry_if_safe(
        attempt.attempt_id, Intent(), contract
    )

    assert next_attempt is not None
    assert next_attempt.attempt_number == 2
    assert next_attempt.idempotency_key == attempt.idempotency_key
    assert next_attempt.state is ExecutionAttemptState.AUTHORIZED
    assert attempts.get(attempt.attempt_id).state is ExecutionAttemptState.ABORTED

    review = coordinator.recovery.get_by_attempt(attempt.attempt_id)
    assert review.decision is RecoveryDecision.SAFE_TO_RETRY
    assert review.verifier_id == "filesystem_independent_v1"


def test_side_effect_confirmation_never_creates_retry():
    _, attempts, coordinator, attempt, contract = _setup(
        status="SIDE_EFFECT_CONFIRMED"
    )

    next_attempt = coordinator.retry_if_safe(
        attempt.attempt_id, Intent(), contract
    )

    assert next_attempt is None
    assert attempts.get(attempt.attempt_id).state is ExecutionAttemptState.RUNNING


def test_quarantine_never_creates_retry():
    _, attempts, coordinator, attempt, contract = _setup(status="QUARANTINED")

    next_attempt = coordinator.retry_if_safe(
        attempt.attempt_id, Intent(), contract
    )

    assert next_attempt is None
    assert attempts.get(attempt.attempt_id).state is ExecutionAttemptState.RUNNING


def test_retry_if_safe_opens_and_resolves_recovery_automatically():
    _, attempts, coordinator, attempt, contract = _setup()

    next_attempt = coordinator.retry_if_safe(attempt.attempt_id, Intent(), contract)

    assert next_attempt.attempt_number == 2
    review = coordinator.recovery.get_by_attempt(attempt.attempt_id)
    assert review.decision is RecoveryDecision.SAFE_TO_RETRY


def test_recovery_is_resolved_before_retry_attempt_is_created():
    _, attempts, coordinator, attempt, contract = _setup()

    next_attempt = coordinator.retry_if_safe(attempt.attempt_id, Intent(), contract)

    review = coordinator.recovery.get_by_attempt(attempt.attempt_id)
    assert review.decision is RecoveryDecision.SAFE_TO_RETRY
    assert review.outcome_id == "recovery-outcome-1"
    assert next_attempt.attempt_number == 2
