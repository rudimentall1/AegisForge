


import sqlite3
from datetime import datetime, timedelta, timezone
import threading

import pytest

from shared.agent_authority import AgentAuthorityRegistry
from shared.agent_identity_signing import AgentIdentitySigner
from shared.capability_grant import intent_hash, evidence_hash
from shared.capability_policy import ActionIntent, CapabilityPolicy
from shared.capability_signing import CapabilitySigner
from shared.execution_retry_authorizer import ExecutionRetryAuthorizer
from shared.signed_action_intent import ActionIntentSigner

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
from shared.trust_evaluation import TrustDecision


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
            evidence_ids=(),
            evidence_hash=evidence_hash(()),
            authorized_action="delete",
            authorized_target="target",
            authorized_scope="scope",
            issued_at="2026-10-03T00:00:00+00:00",
            expires_at="2026-10-03T01:00:00+00:00",
            nonce=grant_id + "-nonce",
            outcome_contract={"type": "state_match", "verifier": "filesystem_independent_v1", "expected_state": "ABSENT"},
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
    assert attempts.get(attempt.attempt_id).state is ExecutionAttemptState.RECOVERED
    assert attempts.get(attempt.attempt_id).error == "recovery_verified_side_effect_confirmed"


def test_quarantine_never_creates_retry():
    _, attempts, coordinator, attempt, contract = _setup(status="QUARANTINED")

    next_attempt = coordinator.retry_if_safe(
        attempt.attempt_id, Intent(), contract
    )

    assert next_attempt is None
    assert attempts.get(attempt.attempt_id).state is ExecutionAttemptState.ABORTED
    assert attempts.get(attempt.attempt_id).error == "recovery_quarantined"


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


def test_retry_authorizer_module_imports_and_issues_new_grant():
    db = sqlite3.connect(":memory:")
    registry = AgentAuthorityRegistry(db)
    registry.register("agent-1", CapabilityPolicy.VERSION)
    intent = ActionIntent(agent_id="agent-1", role="developer", action="run_tests", target="staging", resource="service", destination="staging", data_scope="artifact", read_only=True)
    signed = ActionIntentSigner(AgentIdentitySigner.generate("agent-1", "developer")).sign(intent)
    attempt = ExecutionAttemptStore(db).create("task-1", "old-grant", intent_hash(intent), "operation-1")
    fresh = ExecutionRetryAuthorizer(registry, CapabilitySigner.generate()).authorize(attempt=attempt, intent=intent, signed_action_intent=signed)
    assert fresh.grant.grant_id != attempt.grant_id
    assert fresh.grant.authority_epoch == registry.get("agent-1").authority_epoch



def test_retry_authorizer_is_used_directly_by_coordinator():
    db = sqlite3.connect(":memory:")

    authority_registry = AgentAuthorityRegistry(db)
    authority_registry.register("agent-1", CapabilityPolicy.VERSION)
    authority_registry.record_trust(
        "agent-1",
        TrustDecision(
            status="TRUSTED",
            reason="test",
            proof_id="proof-retry-authority",
            verifier="test",
        ),
    )

    identity_signer = AgentIdentitySigner.generate("agent-1", "developer")
    intent = ActionIntent(
        agent_id="agent-1",
        role="developer",
        action="delete",
        target="staging",
        resource="service",
        destination="staging",
        data_scope="artifact",
        read_only=True,
        parameters={
            "outcome_contract": {
                "type": "state_match",
                "verifier": "filesystem_independent_v1",
                "expected_state": "ABSENT",
            }
        },
    )
    signed_intent = ActionIntentSigner(identity_signer).sign(intent)

    attempt_store = ExecutionAttemptStore(db)
    attempt = attempt_store.create(
        "task-1",
        "old-grant",
        intent_hash(intent),
        "operation-1",
    )
    attempt = attempt_store.transition(
        attempt.attempt_id,
        ExecutionAttemptState.LEASED,
    )
    attempt = attempt_store.transition(
        attempt.attempt_id,
        ExecutionAttemptState.RUNNING,
    )

    verifier_registry = OutcomeVerifierRegistry()
    verifier_registry.register(
        "fake",
        "state_match",
        "filesystem_independent_v1",
        lambda **kwargs: FakeRecoveryVerifier("SAFE_TO_RETRY"),
    )

    gate = RecordingExecutionGate()
    retry_authorizer = ExecutionRetryAuthorizer(
        authority_registry,
        CapabilitySigner.generate(),
    )

    coordinator = ExecutionRecoveryCoordinator(
        db,
        verifier_registry,
        execution_gate=gate,
        retry_authorizer=retry_authorizer,
    )

    contract = {
        "type": "state_match",
        "verifier": "filesystem_independent_v1",
        "expected_state": "ABSENT",
    }

    next_attempt = coordinator.retry_if_safe(
        attempt.attempt_id,
        intent,
        contract,
        signed_action_intent=signed_intent,
    )

    assert next_attempt is not None
    assert next_attempt.attempt_number == 2
    assert next_attempt.grant_id != attempt.grant_id
    assert next_attempt.intent_hash == attempt.intent_hash
    assert next_attempt.idempotency_key == attempt.idempotency_key
    assert next_attempt.state is ExecutionAttemptState.AUTHORIZED
    assert attempt_store.get(attempt.attempt_id).state is ExecutionAttemptState.ABORTED

    fresh_grant = gate.authorized[-1].grant
    assert fresh_grant.grant_id == next_attempt.grant_id
    assert fresh_grant.authority_epoch == authority_registry.get(
        "agent-1"
    ).authority_epoch


def test_retry_authorization_uses_current_suspended_authority_and_keeps_attempt_running():
    db = sqlite3.connect(":memory:")
    authority_registry = AgentAuthorityRegistry(db)
    authority_registry.register("agent-1", CapabilityPolicy.VERSION)
    authority_registry.record_trust(
        "agent-1",
        TrustDecision(
            status="TRUSTED",
            reason="test",
            proof_id="proof-retry-authority",
            verifier="test",
        ),
    )

    identity_signer = AgentIdentitySigner.generate("agent-1", "developer")
    intent = ActionIntent(
        agent_id="agent-1",
        role="developer",
        action="delete",
        target="staging",
        resource="service",
        destination="staging",
        data_scope="artifact",
        read_only=True,
        parameters={
            "outcome_contract": {
                "type": "state_match",
                "verifier": "filesystem_independent_v1",
                "expected_state": "ABSENT",
            }
        },
    )
    signed_intent = ActionIntentSigner(identity_signer).sign(intent)

    attempt_store = ExecutionAttemptStore(db)
    attempt = attempt_store.create(
        "task-1",
        "old-grant",
        intent_hash(intent),
        "operation-1",
    )
    attempt = attempt_store.transition(
        attempt.attempt_id,
        ExecutionAttemptState.LEASED,
    )
    attempt = attempt_store.transition(
        attempt.attempt_id,
        ExecutionAttemptState.RUNNING,
    )

    verifier_registry = OutcomeVerifierRegistry()
    verifier_registry.register(
        "fake",
        "state_match",
        "filesystem_independent_v1",
        lambda **kwargs: FakeRecoveryVerifier("SAFE_TO_RETRY"),
    )

    gate = RecordingExecutionGate()
    retry_authorizer = ExecutionRetryAuthorizer(
        authority_registry,
        CapabilitySigner.generate(),
    )
    coordinator = ExecutionRecoveryCoordinator(
        db,
        verifier_registry,
        execution_gate=gate,
        retry_authorizer=retry_authorizer,
    )

    authority_registry.suspend("agent-1", "security_incident")

    contract = {
        "type": "state_match",
        "verifier": "filesystem_independent_v1",
        "expected_state": "ABSENT",
    }

    with pytest.raises(
        ExecutionRecoveryCoordinatorError,
        match="retry_reauthorization_failed",
    ):
        coordinator.retry_if_safe(
            attempt.attempt_id,
            intent,
            contract,
            signed_action_intent=signed_intent,
        )

    assert authority_registry.get("agent-1").authority_epoch == 3
    assert authority_registry.get("agent-1").state.value == "SUSPENDED"
    assert attempt_store.get(attempt.attempt_id).state is ExecutionAttemptState.RUNNING
    assert gate.authorized == []


def test_direct_retry_authorizer_requires_signed_action_intent():
    db = sqlite3.connect(":memory:")

    authority_registry = AgentAuthorityRegistry(db)
    authority_registry.register("agent-1", CapabilityPolicy.VERSION)

    verifier_registry = OutcomeVerifierRegistry()
    verifier_registry.register(
        "fake",
        "state_match",
        "filesystem_independent_v1",
        lambda **kwargs: FakeRecoveryVerifier("SAFE_TO_RETRY"),
    )

    gate = RecordingExecutionGate()
    retry_authorizer = ExecutionRetryAuthorizer(
        authority_registry,
        CapabilitySigner.generate(),
    )

    coordinator = ExecutionRecoveryCoordinator(
        db,
        verifier_registry,
        execution_gate=gate,
        retry_authorizer=retry_authorizer,
    )

    intent = ActionIntent(
        agent_id="agent-1",
        role="developer",
        action="delete",
        target="staging",
        resource="service",
        destination="staging",
        data_scope="artifact",
        read_only=True,
    )

    attempt_store = ExecutionAttemptStore(db)
    attempt = attempt_store.create(
        "task-1",
        "old-grant",
        intent_hash(intent),
        "operation-1",
    )
    attempt = attempt_store.transition(
        attempt.attempt_id,
        ExecutionAttemptState.LEASED,
    )
    attempt = attempt_store.transition(
        attempt.attempt_id,
        ExecutionAttemptState.RUNNING,
    )

    contract = {
        "type": "state_match",
        "verifier": "filesystem_independent_v1",
        "expected_state": "ABSENT",
    }

    with pytest.raises(
        ExecutionRecoveryCoordinatorError,
        match="signed_action_intent_required",
    ):
        coordinator.retry_if_safe(
            attempt.attempt_id,
            intent,
            contract,
        )

    assert attempt_store.get(
        attempt.attempt_id
    ).state is ExecutionAttemptState.RUNNING

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


def test_crash_after_side_effect_before_receipt_blocks_retry_with_real_filesystem_verifier(tmp_path):
    from shared.capability_grant import issue_capability_grant

    db = sqlite3.connect(":memory:")
    authority_registry = AgentAuthorityRegistry(db)
    authority_registry.register("agent-1", CapabilityPolicy.VERSION)
    authority_registry.record_trust(
        "agent-1",
        TrustDecision("TRUSTED", "test", "proof-crash-recovery", "test"),
    )
    signer = CapabilitySigner.generate()
    identity_signer = AgentIdentitySigner.generate("agent-1", "developer")

    target = tmp_path / "workspace" / "obsolete.txt"
    target.parent.mkdir()
    target.write_text("must-not-be-recreated")
    intent = ActionIntent(
        agent_id="agent-1",
        role="developer",
        action="delete",
        target="workspace/obsolete.txt",
        resource="staging_filesystem",
        destination="staging",
        data_scope="source_code",
        irreversible=True,
        requires_filesystem=True,
        read_only=False,
        evidence_required=True,
        parameters={
            "outcome_contract": {
                "type": "state_match",
                "verifier": "filesystem_independent_v1",
                "expected_state": "ABSENT",
            }
        },
    )
    signed_intent = ActionIntentSigner(identity_signer).sign(intent)
    authority = authority_registry.get("agent-1")
    grant = issue_capability_grant(
        "task-crash-recovery",
        intent,
        CapabilityPolicy.VERSION,
        evidence_ids=["ev-1"],
        authorized_scope="staging",
        authority_state=authority.state,
        authority_context=authority,
        signed_action_intent=signed_intent,
    )
    grant = signer.sign(grant)
    gate = ExecutionGate(db, signer=signer, authority_registry=authority_registry)

    def side_effect_then_crash():
        target.unlink()
        raise SystemExit("simulated_process_crash_after_side_effect")

    with pytest.raises(SystemExit, match="simulated_process_crash_after_side_effect"):
        gate.execute(
            grant,
            intent,
            side_effect_then_crash,
            ["ev-1"],
            executor_id="direct-test-executor",
            executor_version="1",
            executor_identity_epoch=1,
            idempotency_key="crash-after-side-effect-1",
        )

    attempt = gate.attempt_store.find_by_idempotency_key("crash-after-side-effect-1")
    assert attempt.state is ExecutionAttemptState.RUNNING
    assert attempt.receipt_id in ("", None)
    assert not target.exists()

    verifier_registry = OutcomeVerifierRegistry()
    verifier_registry.register(
        "filesystem",
        "state_match",
        "filesystem_independent_v1",
        lambda root, **kwargs: __import__("shared.outcome_verifier", fromlist=["FilesystemOutcomeVerifier"]).FilesystemOutcomeVerifier(root),
    )
    retry_gate = RecordingExecutionGate()
    coordinator = ExecutionRecoveryCoordinator(
        db,
        verifier_registry,
        execution_gate=retry_gate,
    )
    contract = {
        "type": "state_match",
        "verifier": "filesystem_independent_v1",
        "expected_state": "ABSENT",
    }

    next_attempt = coordinator.retry_if_safe(
        attempt.attempt_id,
        intent,
        contract,
        root=tmp_path,
    )

    assert next_attempt is None
    assert retry_gate.authorized == []
    recovered = coordinator.recovery.get_by_attempt(attempt.attempt_id)
    assert recovered.decision is RecoveryDecision.SIDE_EFFECT_CONFIRMED
    assert recovered.verifier_id == "filesystem_independent_v1"
    assert recovered.outcome_id
    assert recovered.idempotency_key == attempt.idempotency_key
    assert coordinator.attempts.get(attempt.attempt_id).state is ExecutionAttemptState.RECOVERED
    assert coordinator.attempts.get(attempt.attempt_id).error == "recovery_verified_side_effect_confirmed"
    assert coordinator.attempts.find_by_idempotency_key(attempt.idempotency_key).attempt_number == 1



def test_retry_claim_allows_only_one_concurrent_reauthorization(tmp_path):
    import threading

    db_path = tmp_path / "recovery.sqlite"
    db1 = sqlite3.connect(db_path, timeout=5, check_same_thread=False)
    db2 = sqlite3.connect(db_path, timeout=5, check_same_thread=False)
    attempts1 = ExecutionAttemptStore(db1)
    attempt = attempts1.create("task-1", "grant-1", "intent-1", "operation-1")
    attempts1.transition(attempt.attempt_id, ExecutionAttemptState.LEASED)
    attempts1.transition(attempt.attempt_id, ExecutionAttemptState.RUNNING)

    registry1 = OutcomeVerifierRegistry()
    registry1.register(
        "fake", "state_match", "filesystem_independent_v1",
        lambda **kwargs: FakeRecoveryVerifier("SAFE_TO_RETRY"),
    )
    registry2 = OutcomeVerifierRegistry()
    registry2.register(
        "fake", "state_match", "filesystem_independent_v1",
        lambda **kwargs: FakeRecoveryVerifier("SAFE_TO_RETRY"),
    )
    gate1 = RecordingExecutionGate()
    gate2 = RecordingExecutionGate()
    coordinator1 = ExecutionRecoveryCoordinator(db1, registry1, execution_gate=gate1)
    coordinator2 = ExecutionRecoveryCoordinator(db2, registry2, execution_gate=gate2)
    contract = {
        "type": "state_match",
        "verifier": "filesystem_independent_v1",
        "expected_state": "ABSENT",
    }
    review = coordinator1.review(attempt.attempt_id, Intent(), contract)
    entered = threading.Event()
    release = threading.Event()
    calls = []

    def reauthorize(**kwargs):
        calls.append(1)
        entered.set()
        assert release.wait(5)
        return _retry_grant()

    result = {}

    def winner():
        result["value"] = coordinator1.retry_if_safe(
            attempt.attempt_id, Intent(), contract, reauthorize=reauthorize
        )

    thread = threading.Thread(target=winner)
    thread.start()
    assert entered.wait(5)

    with pytest.raises(ExecutionRecoveryCoordinatorError, match="retry_in_progress"):
        coordinator2.retry_if_safe(attempt.attempt_id, Intent(), contract)

    release.set()
    thread.join(5)
    assert not thread.is_alive()
    assert len(calls) == 1
    assert result["value"].attempt_number == 2
    assert gate1.authorized[0].grant.grant_id == "grant-retry-1"
    assert gate2.authorized == []
    assert coordinator1.attempts.get(attempt.attempt_id).state is ExecutionAttemptState.ABORTED

    db1.close()
    db2.close()


def test_authorized_retry_resumes_after_original_attempt_was_aborted(tmp_path):
    db = sqlite3.connect(tmp_path / "recovery.sqlite")
    attempts = ExecutionAttemptStore(db)
    attempt = attempts.create("task-1", "grant-1", "intent-1", "operation-1")
    attempts.transition(attempt.attempt_id, ExecutionAttemptState.LEASED)
    attempts.transition(attempt.attempt_id, ExecutionAttemptState.RUNNING)

    registry = OutcomeVerifierRegistry()
    registry.register(
        "fake",
        "state_match",
        "filesystem_independent_v1",
        lambda **kwargs: FakeRecoveryVerifier("SAFE_TO_RETRY"),
    )
    gate = ExecutionGate(db=db)
    coordinator = ExecutionRecoveryCoordinator(db, registry, execution_gate=gate)
    contract = {
        "type": "state_match",
        "verifier": "filesystem_independent_v1",
        "expected_state": "ABSENT",
    }
    review = coordinator.review(attempt.attempt_id, Intent(), contract)
    coordinator.recovery.claim_retry(review)
    operation = coordinator.recovery.get_retry_operation(review.recovery_id)
    retry_grant = _retry_grant(grant_id=operation[4])
    gate.grant_store.register(retry_grant)
    coordinator.recovery.update_retry_operation(
        review.recovery_id, "AUTHORIZED", claim_token=operation[8]
    )
    attempts.transition(
        attempt.attempt_id,
        ExecutionAttemptState.ABORTED,
        error="recovery_verified_safe_to_retry",
    )

    next_attempt = coordinator.retry_if_safe(
        attempt.attempt_id,
        Intent(),
        contract,
    )

    assert next_attempt.attempt_number == 2
    assert next_attempt.grant_id == retry_grant.grant.grant_id
    operation = coordinator.recovery.get_retry_operation(review.recovery_id)
    assert operation[3] == "CREATED"
    assert operation[5] == next_attempt.attempt_id
    db.close()


def test_existing_retry_attempt_is_recovered_if_process_dies_before_operation_update(tmp_path):
    db = sqlite3.connect(tmp_path / "recovery.sqlite")
    attempts = ExecutionAttemptStore(db)
    attempt = attempts.create("task-1", "grant-1", "intent-1", "operation-1")
    attempts.transition(attempt.attempt_id, ExecutionAttemptState.LEASED)
    attempts.transition(attempt.attempt_id, ExecutionAttemptState.RUNNING)

    registry = OutcomeVerifierRegistry()
    registry.register(
        "fake",
        "state_match",
        "filesystem_independent_v1",
        lambda **kwargs: FakeRecoveryVerifier("SAFE_TO_RETRY"),
    )
    gate = ExecutionGate(db=db)
    coordinator = ExecutionRecoveryCoordinator(db, registry, execution_gate=gate)
    contract = {
        "type": "state_match",
        "verifier": "filesystem_independent_v1",
        "expected_state": "ABSENT",
    }
    review = coordinator.review(attempt.attempt_id, Intent(), contract)
    coordinator.recovery.claim_retry(review)
    operation = coordinator.recovery.get_retry_operation(review.recovery_id)
    retry_grant = _retry_grant(grant_id=operation[4])
    gate.grant_store.register(retry_grant)
    coordinator.recovery.update_retry_operation(
        review.recovery_id, "AUTHORIZED", claim_token=operation[8]
    )
    attempts.transition(
        attempt.attempt_id,
        ExecutionAttemptState.ABORTED,
        error="recovery_verified_safe_to_retry",
    )
    existing = attempts.create(
        task_id=attempt.task_id,
        grant_id=retry_grant.grant.grant_id,
        intent_hash=attempt.intent_hash,
        idempotency_key=attempt.idempotency_key,
        retry=True,
    )

    resumed = coordinator.retry_if_safe(
        attempt.attempt_id,
        Intent(),
        contract,
    )

    assert resumed.attempt_id == existing.attempt_id
    operation = coordinator.recovery.get_retry_operation(review.recovery_id)
    assert operation[3] == "CREATED"
    assert operation[5] == existing.attempt_id
    db.close()


def test_retry_operation_state_machine_rejects_impossible_transitions(tmp_path):
    from shared.execution_recovery import ExecutionRecoveryStore, ExecutionRecoveryError

    db = sqlite3.connect(tmp_path / "recovery.sqlite")
    attempts = ExecutionAttemptStore(db)
    attempt = attempts.create("task-1", "grant-1", "intent-1", "operation-1")
    attempt = attempts.transition(attempt.attempt_id, ExecutionAttemptState.LEASED)
    attempt = attempts.transition(attempt.attempt_id, ExecutionAttemptState.RUNNING)
    store = ExecutionRecoveryStore(db)
    review = store.open(attempt)
    review = store.resolve(
        review.recovery_id,
        RecoveryDecision.SAFE_TO_RETRY,
        verifier_id="verifier-1",
        outcome_id="outcome-1",
    )
    operation, created = store.claim_retry(review)
    assert created is True
    assert operation[3] == "CLAIMED"

    with pytest.raises(ExecutionRecoveryError, match="retry_operation_invalid_transition"):
        store.update_retry_operation(review.recovery_id, "CREATED", retry_attempt_id="attempt-2")

    store.update_retry_operation(review.recovery_id, "AUTHORIZED", claim_token=operation[8])
    with pytest.raises(ExecutionRecoveryError, match="retry_operation_invalid_transition"):
        store.update_retry_operation(review.recovery_id, "CLAIMED")

    with pytest.raises(ExecutionRecoveryError, match="retry_attempt_id_required"):
        store.update_retry_operation(review.recovery_id, "CREATED")

    store.update_retry_operation(review.recovery_id, "CREATED", retry_attempt_id="attempt-2")
    assert store.get_retry_operation(review.recovery_id)[3] == "CREATED"

    with pytest.raises(ExecutionRecoveryError, match="retry_operation_invalid_transition"):
        store.update_retry_operation(review.recovery_id, "AUTHORIZED", claim_token=operation[8])
    with pytest.raises(ExecutionRecoveryError, match="retry_operation_invalid_transition"):
        store.update_retry_operation(review.recovery_id, "CLAIMED")

    assert store.update_retry_operation(
        review.recovery_id, "CREATED", retry_attempt_id="attempt-2"
    )[5] == "attempt-2"
    with pytest.raises(ExecutionRecoveryError, match="retry_operation_state_conflict"):
        store.update_retry_operation(review.recovery_id, "CREATED", retry_attempt_id="attempt-3")
    db.close()


def test_stale_retry_claim_can_be_reclaimed_and_old_token_is_fenced(tmp_path):
    db = sqlite3.connect(tmp_path / "recovery.sqlite")
    attempts = ExecutionAttemptStore(db)
    attempt = attempts.create("task-1", "grant-1", "intent-1", "operation-1")
    attempt = attempts.transition(attempt.attempt_id, ExecutionAttemptState.LEASED)
    attempt = attempts.transition(attempt.attempt_id, ExecutionAttemptState.RUNNING)
    from shared.execution_recovery import ExecutionRecoveryStore, ExecutionRecoveryError

    store = ExecutionRecoveryStore(db)
    review = store.open(attempt)
    review = store.resolve(
        review.recovery_id,
        RecoveryDecision.SAFE_TO_RETRY,
        verifier_id="verifier-1",
        outcome_id="outcome-1",
    )
    initial_now = datetime(2026, 10, 5, tzinfo=timezone.utc)
    first, acquired = store.claim_retry(review, now=initial_now)
    assert acquired is True
    old_token = first[8]
    assert first[9] == (initial_now + timedelta(seconds=store.CLAIM_LEASE_SECONDS)).isoformat()

    stale_now = initial_now + timedelta(seconds=store.CLAIM_LEASE_SECONDS + 1)
    reclaimed, acquired = store.claim_retry(review, now=stale_now)
    assert acquired is True
    assert reclaimed[8] != old_token
    assert reclaimed[9] == (stale_now + timedelta(seconds=store.CLAIM_LEASE_SECONDS)).isoformat()

    with pytest.raises(ExecutionRecoveryError, match="retry_claim_token_conflict"):
        store.update_retry_operation(
            review.recovery_id, "AUTHORIZED", claim_token=old_token, now=stale_now
        )

    store.update_retry_operation(
        review.recovery_id, "AUTHORIZED", claim_token=reclaimed[8], now=stale_now
    )
    assert store.get_retry_operation(review.recovery_id)[3] == "AUTHORIZED"
    db.close()


def test_coordinator_reclaims_stale_claim_and_completes_retry(tmp_path):
    db = sqlite3.connect(tmp_path / "recovery.sqlite")
    attempts = ExecutionAttemptStore(db)
    attempt = attempts.create("task-1", "grant-1", "intent-1", "operation-1")
    attempt = attempts.transition(attempt.attempt_id, ExecutionAttemptState.LEASED)
    attempt = attempts.transition(attempt.attempt_id, ExecutionAttemptState.RUNNING)

    registry = OutcomeVerifierRegistry()
    registry.register(
        "fake",
        "state_match",
        "filesystem_independent_v1",
        lambda **kwargs: FakeRecoveryVerifier("SAFE_TO_RETRY"),
    )
    gate = RecordingExecutionGate()
    coordinator = ExecutionRecoveryCoordinator(db, registry, execution_gate=gate)
    contract = {
        "type": "state_match",
        "verifier": "filesystem_independent_v1",
        "expected_state": "ABSENT",
    }
    review = coordinator.review(attempt.attempt_id, Intent(), contract)
    initial_now = datetime(2026, 10, 5, tzinfo=timezone.utc)
    operation, acquired = coordinator.recovery.claim_retry(review, now=initial_now)
    assert acquired is True
    old_token = operation[8]

    stale_now = initial_now + timedelta(seconds=coordinator.recovery.CLAIM_LEASE_SECONDS + 1)
    calls = []

    def reauthorize(**kwargs):
        calls.append(kwargs)
        return _retry_grant(grant_id=operation[4])

    retry = coordinator.retry_if_safe(
        attempt.attempt_id,
        Intent(),
        contract,
        now=stale_now,
        reauthorize=reauthorize,
    )

    assert len(calls) == 1
    assert len(gate.authorized) == 1
    assert retry.attempt_number == 2
    assert retry.grant_id == operation[4]
    assert coordinator.attempts.get(attempt.attempt_id).state is ExecutionAttemptState.ABORTED
    final_operation = coordinator.recovery.get_retry_operation(review.recovery_id)
    assert final_operation[3] == "CREATED"
    assert final_operation[8] is None
    assert old_token != final_operation[8]
    db.close()



def test_concurrent_stale_retry_reclaim_has_one_winner(tmp_path):
    path = tmp_path / "recovery.sqlite"
    db = sqlite3.connect(path)
    attempts = ExecutionAttemptStore(db)
    attempt = attempts.create("task-1", "grant-1", "intent-1", "operation-1")
    attempt = attempts.transition(attempt.attempt_id, ExecutionAttemptState.LEASED)
    attempt = attempts.transition(attempt.attempt_id, ExecutionAttemptState.RUNNING)
    from shared.execution_recovery import ExecutionRecoveryStore

    store = ExecutionRecoveryStore(db)
    review = store.open(attempt)
    review = store.resolve(
        review.recovery_id,
        RecoveryDecision.SAFE_TO_RETRY,
        verifier_id="verifier-1",
        outcome_id="outcome-1",
    )
    initial_now = datetime(2026, 10, 5, tzinfo=timezone.utc)
    store.claim_retry(review, now=initial_now)
    db.close()

    db1 = sqlite3.connect(path, check_same_thread=False)
    db2 = sqlite3.connect(path, check_same_thread=False)
    store1 = ExecutionRecoveryStore(db1)
    store2 = ExecutionRecoveryStore(db2)
    stale_now = initial_now + timedelta(seconds=store1.CLAIM_LEASE_SECONDS + 1)
    results = []
    barrier = threading.Barrier(2)

    def reclaim(store):
        barrier.wait()
        results.append(store.claim_retry(review, now=stale_now)[1])

    t1 = threading.Thread(target=reclaim, args=(store1,))
    t2 = threading.Thread(target=reclaim, args=(store2,))
    t1.start(); t2.start(); t1.join(5); t2.join(5)
    assert not t1.is_alive() and not t2.is_alive()
    assert sorted(results) == [False, True]
    db1.close()
    db2.close()


def test_recover_stale_running_routes_candidates_through_coordinator():
    _, attempts, coordinator, attempt, contract = _setup()
    stale_now = datetime.fromisoformat(attempts.get(attempt.attempt_id).lease_expires_at) + timedelta(seconds=1)
    calls = []

    def context_factory(candidate):
        calls.append(candidate.attempt_id)
        return {
            "intent": Intent(),
            "contract": contract,
            "kwargs": {"reauthorize": lambda **_: _retry_grant()},
        }

    results = coordinator.recover_stale_running(
        context_factory,
        now=stale_now,
    )

    assert calls == [attempt.attempt_id]
    assert results[0][0] == attempt.attempt_id
    assert results[0][1].attempt_number == 2
    assert attempts.get(attempt.attempt_id).state is ExecutionAttemptState.ABORTED


def test_recover_stale_running_does_not_touch_fresh_attempt():
    _, attempts, coordinator, attempt, contract = _setup()
    fresh_now = datetime.fromisoformat(attempts.get(attempt.attempt_id).lease_expires_at) - timedelta(seconds=1)
    calls = []

    def context_factory(candidate):
        calls.append(candidate.attempt_id)
        return {"intent": Intent(), "contract": contract}

    results = coordinator.recover_stale_running(
        context_factory,
        now=fresh_now,
    )

    assert results == []
    assert calls == []
    assert attempts.get(attempt.attempt_id).state is ExecutionAttemptState.RUNNING


def test_recover_stale_running_requires_complete_context():
    _, attempts, coordinator, attempt, _ = _setup()
    stale_now = datetime.fromisoformat(attempts.get(attempt.attempt_id).lease_expires_at) + timedelta(seconds=1)

    with pytest.raises(
        ExecutionRecoveryCoordinatorError,
        match="recovery_context_incomplete",
    ):
        coordinator.recover_stale_running(
            lambda candidate: {"intent": Intent()},
            now=stale_now,
        )

    assert attempts.get(attempt.attempt_id).state is ExecutionAttemptState.RUNNING

def test_recover_stale_running_skips_receipt_race_without_retry():
    _, attempts, coordinator, attempt, contract = _setup()
    stale_now = datetime.fromisoformat(
        attempts.get(attempt.attempt_id).lease_expires_at
    ) + timedelta(seconds=1)
    calls = []

    def context_factory(candidate):
        calls.append(candidate.attempt_id)
        coordinator.attempts.db.execute(
            "UPDATE execution_attempts SET receipt_id=? WHERE attempt_id=?",
            ("receipt-race", candidate.attempt_id),
        )
        coordinator.attempts.db.commit()
        return {
            "intent": Intent(),
            "contract": contract,
            "kwargs": {"reauthorize": lambda **_: _retry_grant()},
        }

    results = coordinator.recover_stale_running(
        context_factory,
        now=stale_now,
    )

    assert calls == [attempt.attempt_id]
    assert results == [(attempt.attempt_id, None)]
    current = attempts.get(attempt.attempt_id)
    assert current.state is ExecutionAttemptState.RUNNING
    assert current.receipt_id == "receipt-race"
    assert coordinator.recovery.get_by_attempt(attempt.attempt_id) is None
