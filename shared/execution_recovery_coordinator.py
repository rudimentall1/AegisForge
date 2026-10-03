from shared.execution_attempt import ExecutionAttemptState, ExecutionAttemptStore, ExecutionAttemptError
from shared.execution_recovery import ExecutionRecoveryError, ExecutionRecoveryStore, RecoveryDecision
from shared.outcome_verifier_registry import OutcomeVerifierRegistry, OutcomeVerifierRegistryError


class ExecutionRecoveryCoordinatorError(ValueError):
    pass


class ExecutionRecoveryCoordinator:
    """Turn an independently verified recovery decision into a safe retry boundary.

    This layer deliberately does not execute the retry. It closes the original
    attempt and creates the next attempt only when an independent verifier has
    established that retry is safe.
    """

    def __init__(self, db, verifier_registry: OutcomeVerifierRegistry):
        if db is None:
            raise ExecutionRecoveryCoordinatorError("database_required")
        if not isinstance(verifier_registry, OutcomeVerifierRegistry):
            raise ExecutionRecoveryCoordinatorError("verifier_registry_required")
        self.attempts = ExecutionAttemptStore(db)
        self.recovery = ExecutionRecoveryStore(db)
        self.verifiers = verifier_registry

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

    def retry_if_safe(self, attempt_id, intent, contract, action=None, now=None,
                      **factory_kwargs):
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

        # Close the ambiguous execution before creating another attempt. The
        # original side effect has already been independently classified safe.
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
                task_id=attempt.task_id,
                grant_id=attempt.grant_id,
                intent_hash=attempt.intent_hash,
                idempotency_key=attempt.idempotency_key,
                now=now,
                retry=True,
            )
        except ExecutionAttemptError as exc:
            raise ExecutionRecoveryCoordinatorError(
                "retry_attempt_create_failed"
            ) from exc
