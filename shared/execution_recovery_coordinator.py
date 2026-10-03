from shared.execution_attempt import ExecutionAttemptState, ExecutionAttemptStore, ExecutionAttemptError
from shared.execution_recovery import ExecutionRecoveryError, ExecutionRecoveryStore, RecoveryDecision
from shared.outcome_verifier_registry import OutcomeVerifierRegistry, OutcomeVerifierRegistryError
from shared.execution_gate import ExecutionGate, ExecutionGateError
from shared.capability_signing import SignedCapabilityGrant


class ExecutionRecoveryCoordinatorError(ValueError):
    pass


class ExecutionRecoveryCoordinator:
    """Turn an independently verified recovery decision into a safe retry boundary.

    This layer deliberately does not execute the retry. It closes the original
    attempt and creates the next attempt only when an independent verifier has
    established that retry is safe.
    """

    def __init__(self, db, verifier_registry: OutcomeVerifierRegistry, execution_gate=None):
        if db is None:
            raise ExecutionRecoveryCoordinatorError("database_required")
        if not isinstance(verifier_registry, OutcomeVerifierRegistry):
            raise ExecutionRecoveryCoordinatorError("verifier_registry_required")
        if execution_gate is not None and not isinstance(execution_gate, ExecutionGate):
            raise ExecutionRecoveryCoordinatorError("execution_gate_required")
        self.attempts = ExecutionAttemptStore(db)
        self.recovery = ExecutionRecoveryStore(db)
        self.verifiers = verifier_registry
        self.execution_gate = execution_gate

    def review(self, attempt_id, intent, contract, action=None, **factory_kwargs):
        attempt = self.attempts.get(attempt_id)
        review = self.recovery.open(attempt)
        if review.decision != RecoveryDecision.UNKNOWN:
            return review
        try:
            outcome = self.verifiers.verify_recovery(
                contract, intent, action=action, **factory_kwargs
            )
            return self.recovery.resolve_verified(review.recovery_id, outcome)
        except (OutcomeVerifierRegistryError, ExecutionRecoveryError):
            raise

    def _reauthorize_retry(self, attempt, intent, reauthorize, evidence_ids=(), now=None):
        if not callable(reauthorize):
            raise ExecutionRecoveryCoordinatorError("reauthorizer_required")
        try:
            signed_grant = reauthorize(attempt=attempt, intent=intent, now=now)
        except Exception as exc:
            raise ExecutionRecoveryCoordinatorError(
                "retry_reauthorization_failed"
            ) from exc
        if not isinstance(signed_grant, SignedCapabilityGrant):
            raise ExecutionRecoveryCoordinatorError("reauthorizer_must_return_signed_grant")
        if signed_grant.grant.grant_id == attempt.grant_id:
            raise ExecutionRecoveryCoordinatorError("retry_grant_must_be_new")
        if signed_grant.grant.task_id != attempt.task_id:
            raise ExecutionRecoveryCoordinatorError("retry_grant_task_mismatch")
        if signed_grant.grant.intent_hash != attempt.intent_hash:
            raise ExecutionRecoveryCoordinatorError("retry_grant_intent_mismatch")
        if self.execution_gate is None:
            raise ExecutionRecoveryCoordinatorError("execution_gate_required")
        try:
            self.execution_gate.authorize(
                signed_grant,
                intent,
                evidence_ids=evidence_ids,
                now=now,
            )
        except ExecutionGateError as exc:
            raise ExecutionRecoveryCoordinatorError(
                "retry_reauthorization_failed"
            ) from exc
        return signed_grant

    def retry_if_safe(self, attempt_id, intent, contract, action=None, now=None,
                      reauthorize=None, evidence_ids=(), **factory_kwargs):
        attempt = self.attempts.get(attempt_id)
        review = self.recovery.get_by_attempt(attempt_id)
        if review is None or review.decision == RecoveryDecision.UNKNOWN:
            review = self.review(
                attempt_id, intent, contract, action=action, **factory_kwargs
            )

        if review.decision != RecoveryDecision.SAFE_TO_RETRY:
            return None

        current = self.attempts.get(attempt_id)
        if current.state != ExecutionAttemptState.RUNNING:
            raise ExecutionRecoveryCoordinatorError("retry_requires_running_attempt")

        # Re-authorize against the current authority/policy before closing the
        # original attempt. A retry must never inherit the old grant.
        retry_grant = self._reauthorize_retry(
            current, intent, reauthorize, evidence_ids=evidence_ids, now=now
        )

        # Only after current authority has approved the new grant do we close
        # the ambiguous execution and create the next attempt.
        try:
            self.attempts.transition(
                attempt_id,
                ExecutionAttemptState.ABORTED,
                now=now,
                error="recovery_verified_safe_to_retry",
            )
        except ExecutionAttemptError as exc:
            raise ExecutionRecoveryCoordinatorError(
                "original_attempt_close_failed"
            ) from exc

        try:
            return self.attempts.create(
                task_id=current.task_id,
                grant_id=retry_grant.grant.grant_id,
                intent_hash=current.intent_hash,
                idempotency_key=current.idempotency_key,
                now=now,
                retry=True,
            )
        except ExecutionAttemptError as exc:
            raise ExecutionRecoveryCoordinatorError(
                "retry_attempt_create_failed"
            ) from exc
