import sqlite3

import pytest

from shared.execution_attempt import ExecutionAttemptState, ExecutionAttemptStore
from shared.execution_recovery import (
    ExecutionRecoveryError,
    ExecutionRecoveryStore,
    RecoveryDecision,
)


def _attempt_store():
    return ExecutionAttemptStore(sqlite3.connect(":memory:"))


def _running_attempt():
    store = _attempt_store()
    attempt = store.create("task-1", "grant-1", "intent-1", "operation-1")
    attempt = store.transition(attempt.attempt_id, ExecutionAttemptState.LEASED)
    attempt = store.transition(
        attempt.attempt_id,
        ExecutionAttemptState.RUNNING,
        executor_id="executor-1",
        executor_version="1",
        executor_identity_epoch=1,
    )
    return store.db, store, attempt


def test_open_recovery_review_for_crashed_running_attempt():
    db, _, attempt = _running_attempt()
    recovery = ExecutionRecoveryStore(db)

    review = recovery.open(attempt)

    assert review.decision is RecoveryDecision.UNKNOWN
    assert review.attempt_id == attempt.attempt_id
    assert review.idempotency_key == "operation-1"


def test_open_recovery_review_is_idempotent():
    db, _, attempt = _running_attempt()
    recovery = ExecutionRecoveryStore(db)

    first = recovery.open(attempt)
    second = recovery.open(attempt)

    assert second.recovery_id == first.recovery_id


def test_recovery_rejects_non_running_attempt():
    store = _attempt_store()
    attempt = store.create("task-1", "grant-1", "intent-1", "operation-1")
    recovery = ExecutionRecoveryStore(store.db)

    with pytest.raises(ExecutionRecoveryError, match="recovery_requires_running_attempt"):
        recovery.open(attempt)


def test_side_effect_confirmed_blocks_retry():
    db, _, attempt = _running_attempt()
    recovery = ExecutionRecoveryStore(db)
    review = recovery.open(attempt)

    resolved = recovery.resolve(
        review.recovery_id,
        RecoveryDecision.SIDE_EFFECT_CONFIRMED,
        verifier_id="filesystem_independent_v1",
        outcome_id="outcome-1",
        reason="external state confirms the side effect",
    )

    assert resolved.decision is RecoveryDecision.SIDE_EFFECT_CONFIRMED
    assert recovery.can_retry(review.recovery_id) is False


def test_verified_recovery_outcome_controls_retry():
    db, _, attempt = _running_attempt()
    recovery = ExecutionRecoveryStore(db)
    review = recovery.open(attempt)

    resolved = recovery.resolve_verified(
        review.recovery_id,
        {"status": "SAFE_TO_RETRY", "verifier": "filesystem_independent_v1", "outcome_id": "verified-1"},
    )

    assert resolved.decision is RecoveryDecision.SAFE_TO_RETRY
    assert recovery.can_retry(review.recovery_id) is True


def test_verified_recovery_requires_verifier_and_outcome_id():
    db, _, attempt = _running_attempt()
    recovery = ExecutionRecoveryStore(db)
    review = recovery.open(attempt)

    with pytest.raises(ExecutionRecoveryError, match="recovery_verifier_required"):
        recovery.resolve_verified(review.recovery_id, {"status": "SAFE_TO_RETRY", "outcome_id": "x"})
    with pytest.raises(ExecutionRecoveryError, match="recovery_outcome_id_required"):
        recovery.resolve_verified(review.recovery_id, {"status": "SAFE_TO_RETRY", "verifier": "filesystem_independent_v1"})


def test_unknown_recovery_cannot_be_retried():
    db, _, attempt = _running_attempt()
    recovery = ExecutionRecoveryStore(db)
    review = recovery.open(attempt)

    assert review.decision is RecoveryDecision.UNKNOWN
    assert recovery.can_retry(review.recovery_id) is False


def test_safe_to_retry_requires_independent_verification():
    db, _, attempt = _running_attempt()
    recovery = ExecutionRecoveryStore(db)
    review = recovery.open(attempt)

    with pytest.raises(ExecutionRecoveryError, match="retry_verifier_required"):
        recovery.resolve(
            review.recovery_id,
            RecoveryDecision.SAFE_TO_RETRY,
            outcome_id="outcome-2",
        )


def test_safe_to_retry_requires_outcome_id():
    db, _, attempt = _running_attempt()
    recovery = ExecutionRecoveryStore(db)
    review = recovery.open(attempt)

    with pytest.raises(ExecutionRecoveryError, match="outcome_id_required"):
        recovery.resolve(
            review.recovery_id,
            RecoveryDecision.SAFE_TO_RETRY,
            verifier_id="filesystem_independent_v1",
        )


def test_safe_to_retry_is_explicit_and_not_automatic():
    db, _, attempt = _running_attempt()
    recovery = ExecutionRecoveryStore(db)
    review = recovery.open(attempt)

    resolved = recovery.resolve(
        review.recovery_id,
        RecoveryDecision.SAFE_TO_RETRY,
        verifier_id="filesystem_independent_v1",
        outcome_id="outcome-3",
        reason="independent verifier confirms the prior attempt did not take effect",
    )

    assert resolved.decision is RecoveryDecision.SAFE_TO_RETRY
    assert recovery.can_retry(review.recovery_id) is True

    with pytest.raises(ExecutionRecoveryError, match="recovery_already_resolved"):
        recovery.resolve(
            review.recovery_id,
            RecoveryDecision.SIDE_EFFECT_CONFIRMED,
            verifier_id="filesystem_independent_v1",
            outcome_id="outcome-4",
        )


def test_recovery_rejects_receipted_attempt():
    db, store, attempt = _running_attempt()
    attempt = store.transition(
        attempt.attempt_id,
        ExecutionAttemptState.SUCCEEDED,
        receipt_id="receipt-1",
    )
    recovery = ExecutionRecoveryStore(db)

    with pytest.raises(ExecutionRecoveryError, match="recovery_requires_running_attempt"):
        recovery.open(attempt)
