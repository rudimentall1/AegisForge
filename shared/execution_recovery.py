from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import sqlite3
import uuid

from shared.execution_attempt import ExecutionAttempt, ExecutionAttemptError


SCHEMA_VERSION = "execution-recovery-v1"


class ExecutionRecoveryError(ValueError):
    pass


class RecoveryDecision(str, Enum):
    UNKNOWN = "UNKNOWN"
    SIDE_EFFECT_CONFIRMED = "SIDE_EFFECT_CONFIRMED"
    SAFE_TO_RETRY = "SAFE_TO_RETRY"
    QUARANTINED = "QUARANTINED"


@dataclass(frozen=True)
class RecoveryReview:
    recovery_id: str
    attempt_id: str
    task_id: str
    idempotency_key: str
    decision: RecoveryDecision
    verifier_id: str = ""
    outcome_id: str = ""
    reason: str = ""
    reviewed_at: str = ""

    def to_dict(self):
        return {
            "schema_version": SCHEMA_VERSION,
            "recovery_id": self.recovery_id,
            "attempt_id": self.attempt_id,
            "task_id": self.task_id,
            "idempotency_key": self.idempotency_key,
            "decision": self.decision.value,
            "verifier_id": self.verifier_id,
            "outcome_id": self.outcome_id,
            "reason": self.reason,
            "reviewed_at": self.reviewed_at,
        }


class ExecutionRecoveryStore:
    TABLE = "execution_recovery_reviews"

    def __init__(self, db):
        if db is None:
            raise ExecutionRecoveryError("database_required")
        self.db = db
        self.db.execute(f"""
            CREATE TABLE IF NOT EXISTS {self.TABLE} (
                recovery_id TEXT PRIMARY KEY,
                attempt_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                decision TEXT NOT NULL,
                verifier_id TEXT,
                outcome_id TEXT,
                reason TEXT,
                reviewed_at TEXT NOT NULL
            )
        """)
        self.db.execute(
            f"CREATE UNIQUE INDEX IF NOT EXISTS uq_{self.TABLE}_attempt "
            f"ON {self.TABLE}(attempt_id)"
        )
        self.db.commit()

    @staticmethod
    def _now(now=None):
        return now or datetime.now(timezone.utc)

    def open(self, attempt: ExecutionAttempt, now=None):
        if not isinstance(attempt, ExecutionAttempt):
            raise ExecutionRecoveryError("attempt_required")
        if attempt.state.value != "RUNNING":
            raise ExecutionRecoveryError("recovery_requires_running_attempt")
        if attempt.receipt_id:
            raise ExecutionRecoveryError("recovery_receipt_already_recorded")

        existing = self.get_by_attempt(attempt.attempt_id)
        if existing is not None:
            return existing

        review = RecoveryReview(
            recovery_id="recovery_" + uuid.uuid4().hex,
            attempt_id=attempt.attempt_id,
            task_id=attempt.task_id,
            idempotency_key=attempt.idempotency_key,
            decision=RecoveryDecision.UNKNOWN,
            reviewed_at=self._now(now).isoformat(),
        )
        try:
            self.db.execute(
                f"""INSERT INTO {self.TABLE}
                (recovery_id,attempt_id,task_id,idempotency_key,decision,reviewed_at)
                VALUES (?,?,?,?,?,?)""",
                (
                    review.recovery_id,
                    review.attempt_id,
                    review.task_id,
                    review.idempotency_key,
                    review.decision.value,
                    review.reviewed_at,
                ),
            )
            self.db.commit()
        except sqlite3.IntegrityError as exc:
            self.db.rollback()
            existing = self.get_by_attempt(attempt.attempt_id)
            if existing is not None:
                return existing
            raise ExecutionRecoveryError("recovery_review_conflict") from exc
        return review

    def get(self, recovery_id):
        row = self.db.execute(
            f"""SELECT recovery_id,attempt_id,task_id,idempotency_key,decision,
                       verifier_id,outcome_id,reason,reviewed_at
                FROM {self.TABLE} WHERE recovery_id=?""",
            (str(recovery_id),),
        ).fetchone()
        if row is None:
            raise ExecutionRecoveryError("recovery_not_found")
        try:
            decision = RecoveryDecision(row[4])
        except ValueError as exc:
            raise ExecutionRecoveryError("invalid_recovery_decision") from exc
        return RecoveryReview(*row[:4], decision, *row[5:])

    def get_by_attempt(self, attempt_id):
        row = self.db.execute(
            f"SELECT recovery_id FROM {self.TABLE} WHERE attempt_id=?",
            (str(attempt_id),),
        ).fetchone()
        return self.get(row[0]) if row else None

    def resolve(
        self,
        recovery_id,
        decision,
        verifier_id="",
        outcome_id="",
        reason="",
        now=None,
    ):
        try:
            decision = RecoveryDecision(decision)
        except ValueError as exc:
            raise ExecutionRecoveryError("invalid_recovery_decision") from exc

        if decision == RecoveryDecision.SAFE_TO_RETRY and not str(verifier_id).strip():
            raise ExecutionRecoveryError("retry_verifier_required")
        if decision == RecoveryDecision.SIDE_EFFECT_CONFIRMED and not str(verifier_id).strip():
            raise ExecutionRecoveryError("outcome_verifier_required")
        if decision in {
            RecoveryDecision.SIDE_EFFECT_CONFIRMED,
            RecoveryDecision.SAFE_TO_RETRY,
        } and not str(outcome_id).strip():
            raise ExecutionRecoveryError("outcome_id_required")

        current = self.get(recovery_id)
        if current.decision != RecoveryDecision.UNKNOWN:
            raise ExecutionRecoveryError("recovery_already_resolved")

        reviewed_at = self._now(now).isoformat()
        self.db.execute(
            f"""UPDATE {self.TABLE}
                SET decision=?, verifier_id=?, outcome_id=?, reason=?, reviewed_at=?
                WHERE recovery_id=? AND decision=?""",
            (
                decision.value,
                str(verifier_id or ""),
                str(outcome_id or ""),
                str(reason or ""),
                reviewed_at,
                recovery_id,
                RecoveryDecision.UNKNOWN.value,
            ),
        )
        if self.db.execute("SELECT changes()").fetchone()[0] != 1:
            self.db.rollback()
            raise ExecutionRecoveryError("recovery_state_conflict")
        self.db.commit()
        return self.get(recovery_id)

    def resolve_verified(self, recovery_id, verification, now=None):
        """Resolve only from a verifier-produced recovery outcome."""
        if not isinstance(verification, dict):
            raise ExecutionRecoveryError("verification_required")
        try:
            decision = RecoveryDecision(verification.get("status"))
        except ValueError as exc:
            raise ExecutionRecoveryError("invalid_recovery_verification_status") from exc
        if decision not in {
            RecoveryDecision.SIDE_EFFECT_CONFIRMED,
            RecoveryDecision.SAFE_TO_RETRY,
            RecoveryDecision.QUARANTINED,
        }:
            raise ExecutionRecoveryError("invalid_recovery_verification_status")
        verifier_id = str(verification.get("verifier") or "").strip()
        outcome_id = str(verification.get("outcome_id") or "").strip()
        if not verifier_id:
            raise ExecutionRecoveryError("recovery_verifier_required")
        if not outcome_id:
            raise ExecutionRecoveryError("recovery_outcome_id_required")
        return self.resolve(
            recovery_id,
            decision,
            verifier_id=verifier_id,
            outcome_id=outcome_id,
            reason="independent_outcome_verification",
            now=now,
        )

    def can_retry(self, recovery_id):
        return self.get(recovery_id).decision == RecoveryDecision.SAFE_TO_RETRY
