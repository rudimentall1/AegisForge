import sqlite3

import pytest

from shared.capability_grant import CapabilityGrant
from shared.capability_signing import SignedCapabilityGrant
from shared.execution_gate import ExecutionGate
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


class RecordingExecutionGate(ExecutionGate):
    def __init__(self):
        self.authorized = []

    def authorize(self, grant, intent, evidence_ids=(), now=None):
        self.authorized.append(grant)
        return grant


def _retry_grant(grant_id="grant-retry-1", task_id="task-1", intent_hash="intent-1"):
    return SignedCapabilityGrant(
        grant=CapabilityGrant(
            grant_id=grant_id,
            task_id=task_id,
            agent_id="agent-1",
            authority_epoch=2,
            authority_state="STANDARD",
            intent_hash=intent_hash,
            policy_version="policy-v1",
            authorized_action="delete",
            authorized_target="target",
            authorized_scope="scope",
            issued_at="2026-10-03T00:00:00+00:00",
            expires_at="2026-10-03T01:00:00+00:00",
            nonce=grant_id + "-nonce",
            outcome_contract={},
        ),
        key_id="test-key",
        signature="test-signature",
    )


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
    gate = RecordingExecutionGate()
    coordinator = ExecutionRecoveryCoordinator(db, registry, execution_gate=gate)
    contract = {
        "type": "state_match",
        "verifier": "filesystem_independent_v1",
        "expected_state": "ABSENT",
    }
    return db, attempts, coordinator, attempt, contract


def test_safe_recovery_creates_next_attempt():
    db, attempts, coordinator, attempt, contract = _setup()

    next_attempt = coordinator.retry_if_safe(
        attempt.attempt_id,
        Intent(),
        contract,
        reauthorize=lambda **_: _retry_grant(),
    )

    assert next_attempt is not None
    assert next_attempt.attempt_number == 2
    assert next_attempt.grant_id == "grant-retry-1"
    assert coordinator.execution_gate.authorized[0].grant.grant_id == "grant-retry-1"
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

    next_attempt = coordinator.retry_if_safe(
        attempt.attempt_id,
        Intent(),
        contract,
        reauthorize=lambda **_: _retry_grant(),
    )

    assert next_attempt.attempt_number == 2
    assert next_attempt.grant_id == "grant-retry-1"
    review = coordinator.recovery.get_by_attempt(attempt.attempt_id)
    assert review.decision is RecoveryDecision.SAFE_TO_RETRY


def test_recovery_is_resolved_before_retry_attempt_is_created():
    _, attempts, coordinator, attempt, contract = _setup()

    next_attempt = coordinator.retry_if_safe(
        attempt.attempt_id,
        Intent(),
        contract,
        reauthorize=lambda **_: _retry_grant(),
    )

    review = coordinator.recovery.get_by_attempt(attempt.attempt_id)
    assert review.decision is RecoveryDecision.SAFE_TO_RETRY
    assert review.outcome_id == "recovery-outcome-1"
    assert next_attempt.attempt_number == 2


def test_retry_reauthorization_failure_keeps_original_attempt_running():
    _, attempts, coordinator, attempt, contract = _setup()

    def reject_reauthorization(**_):
        raise ValueError("authority_revoked")

    with pytest.raises(ExecutionRecoveryCoordinatorError, match="retry_reauthorization_failed"):
        coordinator.retry_if_safe(
            attempt.attempt_id,
            Intent(),
            contract,
            reauthorize=reject_reauthorization,
        )

    assert attempts.get(attempt.attempt_id).state is ExecutionAttemptState.RUNNING


def test_retry_cannot_reuse_original_grant():
    _, attempts, coordinator, attempt, contract = _setup()

    with pytest.raises(ExecutionRecoveryCoordinatorError, match="retry_grant_must_be_new"):
        coordinator.retry_if_safe(
            attempt.attempt_id,
            Intent(),
            contract,
            reauthorize=lambda **_: _retry_grant(grant_id=attempt.grant_id),
        )

    assert attempts.get(attempt.attempt_id).state is ExecutionAttemptState.RUNNING
