import sqlite3
from datetime import datetime, timedelta, timezone
import pytest
from shared.execution_attempt import ExecutionAttemptError, ExecutionAttemptState, ExecutionAttemptStore

def store():
    return ExecutionAttemptStore(sqlite3.connect(":memory:"))

def test_create_attempt_starts_authorized():
    s = store()
    a = s.create("task-1", "grant-1", "hash-1", "idem-1")
    assert a.state is ExecutionAttemptState.AUTHORIZED
    assert a.attempt_id.startswith("attempt_")
    assert s.get(a.attempt_id).to_dict()["schema_version"] == "execution-attempt-v1"

def test_idempotency_key_cannot_create_second_logical_execution():
    s = store()
    s.create("task-1", "grant-1", "hash-1", "idem-1")
    with pytest.raises(ExecutionAttemptError, match="idempotency_key_active"):
        s.create("task-1", "grant-1", "hash-1", "idem-1")

def test_lifecycle_authorized_to_running_to_succeeded():
    s = store()
    a = s.create("task-1", "grant-1", "hash-1", "idem-1")
    leased = s.transition(a.attempt_id, "LEASED")
    assert leased.lease_expires_at
    running = s.transition(a.attempt_id, "RUNNING", executor_id="executor", executor_version="1", executor_identity_epoch=2)
    assert running.started_at
    done = s.transition(a.attempt_id, "SUCCEEDED", receipt_id="receipt-1")
    assert done.finished_at
    assert done.receipt_id == "receipt-1"
    assert done.executor_id == "executor"

def test_invalid_transition_is_rejected():
    s = store()
    a = s.create("task-1", "grant-1", "hash-1", "idem-1")
    with pytest.raises(ExecutionAttemptError, match="invalid_transition"):
        s.transition(a.attempt_id, "RUNNING")

def test_terminal_attempt_cannot_transition_again():
    s = store()
    a = s.create("task-1", "grant-1", "hash-1", "idem-1")
    s.transition(a.attempt_id, "LEASED")
    s.transition(a.attempt_id, "RUNNING")
    s.transition(a.attempt_id, "FAILED", error="executor crashed")
    with pytest.raises(ExecutionAttemptError, match="invalid_transition"):
        s.transition(a.attempt_id, "RUNNING")

def test_expired_lease_times_out():
    s = store()
    now = datetime(2026, 10, 3, tzinfo=timezone.utc)
    a = s.create("task-1", "grant-1", "hash-1", "idem-1", now=now)
    leased = s.transition(a.attempt_id, "LEASED", now=now)
    future = datetime.fromisoformat(leased.lease_expires_at) + timedelta(seconds=1)
    expired = s.expire_leases(now=future)
    assert len(expired) == 1
    assert expired[0].state is ExecutionAttemptState.TIMED_OUT
    assert s.get(a.attempt_id).finished_at


def test_terminal_attempt_can_be_retried_with_same_idempotency_key():
    s = store()
    first = s.create("task-1", "grant-1", "hash-1", "idem-1")
    s.transition(first.attempt_id, "LEASED")
    s.transition(first.attempt_id, "RUNNING")
    s.transition(first.attempt_id, "FAILED", error="crash")
    second = s.create("task-1", "grant-2", "hash-1", "idem-1", retry=True)
    assert second.attempt_number == 2
    assert second.attempt_id != first.attempt_id
    assert second.state is ExecutionAttemptState.AUTHORIZED


def test_active_attempt_cannot_be_retried():
    s = store()
    s.create("task-1", "grant-1", "hash-1", "idem-1")
    with pytest.raises(ExecutionAttemptError, match="idempotency_key_active"):
        s.create("task-1", "grant-2", "hash-1", "idem-1", retry=True)


def test_fresh_running_attempt_is_not_stale():
    s = store()
    now = datetime(2026, 10, 5, tzinfo=timezone.utc)
    a = s.create("task-1", "grant-1", "hash-1", "idem-1", now=now)
    leased = s.transition(a.attempt_id, "LEASED", now=now)
    s.transition(a.attempt_id, "RUNNING", now=now)
    before_expiry = datetime.fromisoformat(leased.lease_expires_at) - timedelta(seconds=1)

    assert s.find_stale_running(now=before_expiry) == []
    assert s.get(a.attempt_id).state is ExecutionAttemptState.RUNNING


def test_expired_running_without_receipt_is_recovery_candidate():
    s = store()
    now = datetime(2026, 10, 5, tzinfo=timezone.utc)
    a = s.create("task-1", "grant-1", "hash-1", "idem-1", now=now)
    leased = s.transition(a.attempt_id, "LEASED", now=now)
    s.transition(a.attempt_id, "RUNNING", now=now)
    stale_at = datetime.fromisoformat(leased.lease_expires_at) + timedelta(seconds=1)

    candidates = s.find_stale_running(now=stale_at)

    assert [item.attempt_id for item in candidates] == [a.attempt_id]
    assert candidates[0].state is ExecutionAttemptState.RUNNING
    assert candidates[0].receipt_id is None
    assert s.get(a.attempt_id).state is ExecutionAttemptState.RUNNING


def test_running_attempt_with_receipt_is_not_recovery_candidate():
    s = store()
    now = datetime(2026, 10, 5, tzinfo=timezone.utc)
    a = s.create("task-1", "grant-1", "hash-1", "idem-1", now=now)
    leased = s.transition(a.attempt_id, "LEASED", now=now)
    s.transition(a.attempt_id, "RUNNING", now=now)
    stale_at = datetime.fromisoformat(leased.lease_expires_at) + timedelta(seconds=1)
    s.transition(a.attempt_id, "SUCCEEDED", now=stale_at, receipt_id="receipt-1")

    assert s.find_stale_running(now=stale_at + timedelta(seconds=1)) == []


def test_stale_running_detection_is_read_only_and_repeatable():
    s = store()
    now = datetime(2026, 10, 5, tzinfo=timezone.utc)
    a = s.create("task-1", "grant-1", "hash-1", "idem-1", now=now)
    leased = s.transition(a.attempt_id, "LEASED", now=now)
    s.transition(a.attempt_id, "RUNNING", now=now)
    stale_at = datetime.fromisoformat(leased.lease_expires_at) + timedelta(seconds=1)

    first = s.find_stale_running(now=stale_at)
    second = s.find_stale_running(now=stale_at)

    assert [item.attempt_id for item in first] == [a.attempt_id]
    assert [item.attempt_id for item in second] == [a.attempt_id]
    assert s.get(a.attempt_id).state is ExecutionAttemptState.RUNNING


def test_stale_running_detection_rejects_non_positive_limit():
    s = store()
    with pytest.raises(ExecutionAttemptError, match="limit_must_be_positive"):
        s.find_stale_running(limit=0)
