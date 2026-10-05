from shared.execution_attempt import ExecutionAttemptState, ExecutionAttemptStore, ExecutionAttemptError
from shared.execution_recovery import ExecutionRecoveryError, ExecutionRecoveryStore, RecoveryDecision
from shared.outcome_verifier_registry import OutcomeVerifierRegistry, OutcomeVerifierRegistryError
from shared.execution_gate import ExecutionGate, ExecutionGateError
from shared.capability_signing import SignedCapabilityGrant
from shared.execution_retry_authorizer import ExecutionRetryAuthorizer
from shared.recovery_evidence import RecoveryEvidenceChain


class ExecutionRecoveryCoordinatorError(ValueError):
    pass


class ExecutionRecoveryCoordinator:
    """Turn an independently verified recovery decision into a safe retry boundary.

    This layer deliberately does not execute the retry. It closes the original
    attempt and creates the next attempt only when an independent verifier has
    established that retry is safe.
    """

    def __init__(self, db, verifier_registry: OutcomeVerifierRegistry, execution_gate=None, retry_authorizer=None):
        if db is None:
            raise ExecutionRecoveryCoordinatorError("database_required")
        if not isinstance(verifier_registry, OutcomeVerifierRegistry):
            raise ExecutionRecoveryCoordinatorError("verifier_registry_required")
        if execution_gate is not None and not isinstance(execution_gate, ExecutionGate):
            raise ExecutionRecoveryCoordinatorError("execution_gate_required")
        if retry_authorizer is not None and not isinstance(
            retry_authorizer, ExecutionRetryAuthorizer
        ):
            raise ExecutionRecoveryCoordinatorError("retry_authorizer_required")
        self.attempts = ExecutionAttemptStore(db)
        self.recovery = ExecutionRecoveryStore(db)
        self.recovery_evidence = RecoveryEvidenceChain(db)
        self.verifiers = verifier_registry
        self.execution_gate = execution_gate
        self.retry_authorizer = retry_authorizer

    def review(self, attempt_id, intent, contract, action=None, **factory_kwargs):
        attempt = self.attempts.get(attempt_id)
        review = self.recovery.open(attempt)
        if review.decision != RecoveryDecision.UNKNOWN:
            return review
        self.recovery_evidence.append(
            review.recovery_id,
            attempt.attempt_id,
            "RECOVERY_OPENED",
            {"state": attempt.state.value, "lease_expires_at": attempt.lease_expires_at},
        )
        try:
            outcome = self.verifiers.verify_recovery(
                contract, intent, action=action, **factory_kwargs
            )
            resolved = self.recovery.resolve_verified(review.recovery_id, outcome)
            self.recovery_evidence.append(
                review.recovery_id,
                attempt.attempt_id,
                "VERIFICATION_DECISION",
                {
                    "decision": resolved.decision.value,
                    "verifier_id": resolved.verifier_id,
                    "outcome_id": resolved.outcome_id,
                },
            )
            return resolved
        except (OutcomeVerifierRegistryError, ExecutionRecoveryError):
            raise

    def _reauthorize_retry(
        self,
        attempt,
        intent,
        reauthorize=None,
        signed_action_intent=None,
        evidence_ids=(),
        now=None,
        retry_grant_id=None,
    ):
        if self.retry_authorizer is not None:
            if signed_action_intent is None:
                raise ExecutionRecoveryCoordinatorError(
                    "signed_action_intent_required"
                )
            try:
                signed_grant = self.retry_authorizer.authorize(
                    attempt=attempt,
                    intent=intent,
                    signed_action_intent=signed_action_intent,
                    evidence_ids=evidence_ids,
                    now=now,
                    grant_id=retry_grant_id,
                    nonce=("retry-nonce_" + str(retry_grant_id)) if retry_grant_id else None,
                )
            except Exception as exc:
                raise ExecutionRecoveryCoordinatorError(
                    "retry_reauthorization_failed"
                ) from exc
        else:
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

    def recover_stale_running(
        self,
        context_factory,
        now=None,
        limit=100,
    ):
        """Recover expired RUNNING attempts without treating staleness as proof.

        Detection is read-only and recovery still requires an independent
        outcome verifier. The context factory supplies the intent, contract,
        and optional retry arguments needed by retry_if_safe for each candidate.
        """
        if not callable(context_factory):
            raise ExecutionRecoveryCoordinatorError("context_factory_required")
        candidates = self.attempts.find_stale_running(now=now, limit=limit)
        results = []
        for attempt in candidates:
            context = context_factory(attempt)
            if not isinstance(context, dict):
                raise ExecutionRecoveryCoordinatorError("recovery_context_required")
            if "intent" not in context or "contract" not in context:
                raise ExecutionRecoveryCoordinatorError("recovery_context_incomplete")
            kwargs = dict(context.get("kwargs") or {})
            kwargs.setdefault("now", now)
            try:
                result = self.retry_if_safe(
                    attempt.attempt_id,
                    context["intent"],
                    context["contract"],
                    **kwargs,
                )
            except ExecutionRecoveryError:
                # A stale-candidate snapshot can race with a receipt or a
                # terminal state becoming durable. In that case the candidate
                # is no longer ambiguous and must be skipped, not retried.
                current = self.attempts.get(attempt.attempt_id)
                if current.state != ExecutionAttemptState.RUNNING or current.receipt_id:
                    results.append((attempt.attempt_id, None))
                    continue
                raise
            results.append((attempt.attempt_id, result))
        return results

    def retry_if_safe(
        self,
        attempt_id,
        intent,
        contract,
        action=None,
        now=None,
        reauthorize=None,
        signed_action_intent=None,
        evidence_ids=(),
        **factory_kwargs,
    ):
        attempt = self.attempts.get(attempt_id)
        review = self.recovery.get_by_attempt(attempt_id)
        if review is None or review.decision == RecoveryDecision.UNKNOWN:
            review = self.review(
                attempt_id, intent, contract, action=action, **factory_kwargs
            )

        if review.decision == RecoveryDecision.SIDE_EFFECT_CONFIRMED:
            current = self.attempts.get(attempt_id)
            if current.state == ExecutionAttemptState.RUNNING:
                try:
                    self.attempts.transition(
                        attempt_id,
                        ExecutionAttemptState.RECOVERED,
                        now=now,
                        error="recovery_verified_side_effect_confirmed",
                    )
                except ExecutionAttemptError as exc:
                    raise ExecutionRecoveryCoordinatorError(
                        "recovery_terminalization_failed"
                    ) from exc
            self.recovery_evidence.append(
                review.recovery_id,
                attempt_id,
                "SIDE_EFFECT_CONFIRMED",
                {"outcome_id": review.outcome_id, "verifier_id": review.verifier_id},
                now=now,
            )
            return None

        if review.decision == RecoveryDecision.QUARANTINED:
            current = self.attempts.get(attempt_id)
            if current.state == ExecutionAttemptState.RUNNING:
                try:
                    self.attempts.transition(
                        attempt_id,
                        ExecutionAttemptState.ABORTED,
                        now=now,
                        error="recovery_quarantined",
                    )
                except ExecutionAttemptError as exc:
                    raise ExecutionRecoveryCoordinatorError(
                        "recovery_terminalization_failed"
                    ) from exc
            self.recovery_evidence.append(
                review.recovery_id,
                attempt_id,
                "QUARANTINED",
                {"outcome_id": review.outcome_id, "verifier_id": review.verifier_id},
                now=now,
            )
            return None

        if review.decision != RecoveryDecision.SAFE_TO_RETRY:
            return None

        current = self.attempts.get(attempt_id)
        operation, created = self.recovery.claim_retry(review, now=now)
        operation_state = operation[3]
        retry_grant_id = operation[4]
        retry_attempt_id = operation[5]
        claim_token = operation[8]

        if operation_state == "CREATED" and retry_attempt_id:
            return self.attempts.get(retry_attempt_id)

        if operation_state == "AUTHORIZED" and retry_attempt_id:
            return self.attempts.get(retry_attempt_id)

        if not created and operation_state == "CLAIMED":
            if self.execution_gate is not None and getattr(self.execution_gate, "grant_store", None) is not None:
                persisted = self.execution_gate.grant_store.get_signed(retry_grant_id)
                if persisted is not None:
                    operation = self.recovery.update_retry_operation(
                        review.recovery_id, "AUTHORIZED", now=now, claim_token=claim_token
                    )
                    operation_state = "AUTHORIZED"
                else:
                    raise ExecutionRecoveryCoordinatorError("retry_in_progress")
            else:
                raise ExecutionRecoveryCoordinatorError("retry_in_progress")
        if operation_state == "AUTHORIZED":
            if self.execution_gate is None or getattr(self.execution_gate, "grant_store", None) is None:
                raise ExecutionRecoveryCoordinatorError("retry_authorization_record_required")
            retry_grant = self.execution_gate.grant_store.get_signed(retry_grant_id)
            if retry_grant is None:
                raise ExecutionRecoveryCoordinatorError("retry_authorization_record_missing")
        else:
            retry_grant = self._reauthorize_retry(
                current,
                intent,
                reauthorize=reauthorize,
                signed_action_intent=signed_action_intent,
                evidence_ids=evidence_ids,
                now=now,
                retry_grant_id=retry_grant_id,
            )
            self.recovery.update_retry_operation(
                review.recovery_id, "AUTHORIZED", now=now, claim_token=claim_token
            )
            self.recovery_evidence.append(
                review.recovery_id,
                attempt_id,
                "RETRY_AUTHORIZED",
                {
                    "grant_id": retry_grant.grant.grant_id,
                    "verifier_id": review.verifier_id,
                    "outcome_id": review.outcome_id,
                },
                now=now,
            )

        current = self.attempts.get(attempt_id)
        if current.state == ExecutionAttemptState.RUNNING:
            try:
                self.attempts.transition(
                    attempt_id,
                    ExecutionAttemptState.ABORTED,
                    now=now,
                    error="recovery_verified_safe_to_retry",
                )
                self.recovery_evidence.append(
                    review.recovery_id,
                    attempt_id,
                    "ORIGINAL_ABORTED",
                    {"reason": "recovery_verified_safe_to_retry"},
                    now=now,
                )
            except ExecutionAttemptError as exc:
                raise ExecutionRecoveryCoordinatorError(
                    "original_attempt_close_failed"
                ) from exc
        elif current.state != ExecutionAttemptState.ABORTED:
            raise ExecutionRecoveryCoordinatorError("retry_requires_running_or_aborted_attempt")

        existing_retry = self.attempts.find_by_grant_id(retry_grant.grant.grant_id)
        if existing_retry is not None:
            self.recovery.update_retry_operation(
                review.recovery_id, "CREATED", retry_attempt_id=existing_retry.attempt_id, now=now
            )
            self.recovery_evidence.append(
                review.recovery_id,
                attempt_id,
                "RETRY_CREATED",
                {
                    "retry_attempt_id": existing_retry.attempt_id,
                    "grant_id": retry_grant.grant.grant_id,
                },
                now=now,
            )
            return existing_retry

        try:
            next_attempt = self.attempts.create(
                task_id=current.task_id,
                grant_id=retry_grant.grant.grant_id,
                intent_hash=current.intent_hash,
                idempotency_key=current.idempotency_key,
                now=now,
                retry=True,
            )
            self.recovery.update_retry_operation(
                review.recovery_id, "CREATED", retry_attempt_id=next_attempt.attempt_id, now=now
            )
            self.recovery_evidence.append(
                review.recovery_id,
                attempt_id,
                "RETRY_CREATED",
                {
                    "retry_attempt_id": next_attempt.attempt_id,
                    "grant_id": retry_grant.grant.grant_id,
                },
                now=now,
            )
            return next_attempt
        except ExecutionAttemptError as exc:
            raise ExecutionRecoveryCoordinatorError(
                "retry_attempt_create_failed"
            ) from exc
