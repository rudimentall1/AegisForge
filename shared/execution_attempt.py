from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
import sqlite3
import uuid


SCHEMA_VERSION = "execution-attempt-v1"


class ExecutionAttemptError(ValueError):
    pass


class ExecutionAttemptState(str, Enum):
    AUTHORIZED = "AUTHORIZED"
    LEASED = "LEASED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    ABORTED = "ABORTED"


_TERMINAL = {
    ExecutionAttemptState.SUCCEEDED,
    ExecutionAttemptState.FAILED,
    ExecutionAttemptState.TIMED_OUT,
    ExecutionAttemptState.ABORTED,
}

_ALLOWED = {
    ExecutionAttemptState.AUTHORIZED: {ExecutionAttemptState.LEASED, ExecutionAttemptState.ABORTED},
    ExecutionAttemptState.LEASED: {ExecutionAttemptState.RUNNING, ExecutionAttemptState.TIMED_OUT, ExecutionAttemptState.ABORTED},
    ExecutionAttemptState.RUNNING: {ExecutionAttemptState.SUCCEEDED, ExecutionAttemptState.FAILED, ExecutionAttemptState.TIMED_OUT, ExecutionAttemptState.ABORTED},
    ExecutionAttemptState.SUCCEEDED: set(),
    ExecutionAttemptState.FAILED: set(),
    ExecutionAttemptState.TIMED_OUT: set(),
    ExecutionAttemptState.ABORTED: set(),
}


@dataclass(frozen=True)
class ExecutionAttempt:
    attempt_id: str
    task_id: str
    grant_id: str
    intent_hash: str
    idempotency_key: str
    attempt_number: int
    state: ExecutionAttemptState
    created_at: str
    lease_expires_at: str = ""
    started_at: str = ""
    finished_at: str = ""
    executor_id: str = ""
    executor_version: str = ""
    executor_identity_epoch: int = 0
    receipt_id: str = ""
    error: str = ""

    def to_dict(self):
        return {
            "schema_version": SCHEMA_VERSION,
            "attempt_id": self.attempt_id,
            "task_id": self.task_id,
            "grant_id": self.grant_id,
            "intent_hash": self.intent_hash,
            "idempotency_key": self.idempotency_key,
            "attempt_number": self.attempt_number,
            "state": self.state.value,
            "created_at": self.created_at,
            "lease_expires_at": self.lease_expires_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "executor_id": self.executor_id,
            "executor_version": self.executor_version,
            "executor_identity_epoch": self.executor_identity_epoch,
            "receipt_id": self.receipt_id,
            "error": self.error,
        }


class ExecutionAttemptStore:
    TABLE = "execution_attempts"

    def __init__(self, db):
        if db is None:
            raise ExecutionAttemptError("database_required")
        self.db = db
        self.db.execute(f"""
            CREATE TABLE IF NOT EXISTS {self.TABLE} (
                attempt_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                grant_id TEXT NOT NULL,
                intent_hash TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                attempt_number INTEGER NOT NULL,
                state TEXT NOT NULL,
                created_at TEXT NOT NULL,
                lease_expires_at TEXT,
                started_at TEXT,
                finished_at TEXT,
                executor_id TEXT,
                executor_version TEXT,
                executor_identity_epoch INTEGER NOT NULL DEFAULT 0,
                receipt_id TEXT,
                error TEXT
            )
        """)
        self.db.execute(f"CREATE UNIQUE INDEX IF NOT EXISTS uq_{self.TABLE}_key_number ON {self.TABLE}(idempotency_key, attempt_number)")
        self.db.execute(f"CREATE INDEX IF NOT EXISTS idx_{self.TABLE}_task ON {self.TABLE}(task_id)")
        self.db.execute(f"CREATE INDEX IF NOT EXISTS idx_{self.TABLE}_state ON {self.TABLE}(state)")
        self.db.commit()

    @staticmethod
    def _now(now=None):
        return now or datetime.now(timezone.utc)

    def create(self, task_id, grant_id, intent_hash, idempotency_key, now=None, retry=False):
        for name, value in (
            ("task_id", task_id), ("grant_id", grant_id),
            ("intent_hash", intent_hash), ("idempotency_key", idempotency_key),
        ):
            if not value:
                raise ExecutionAttemptError(f"{name}_required")
        created = self._now(now).isoformat()
        previous = self.find_by_idempotency_key(idempotency_key)
        if previous is not None:
            if previous.state not in _TERMINAL:
                raise ExecutionAttemptError("idempotency_key_active")
            if not retry:
                raise ExecutionAttemptError("idempotency_key_reused")
            attempt_number = previous.attempt_number + 1
        else:
            attempt_number = 1
        attempt = ExecutionAttempt(
            attempt_id="attempt_" + uuid.uuid4().hex,
            task_id=str(task_id),
            grant_id=str(grant_id),
            intent_hash=str(intent_hash),
            idempotency_key=str(idempotency_key),
            attempt_number=attempt_number,
            state=ExecutionAttemptState.AUTHORIZED,
            created_at=created,
        )
        try:
            self.db.execute(
                f"""INSERT INTO {self.TABLE}
                (attempt_id,task_id,grant_id,intent_hash,idempotency_key,attempt_number,state,created_at)
                VALUES (?,?,?,?,?,?,?,?)""",
                (attempt.attempt_id, attempt.task_id, attempt.grant_id,
                 attempt.intent_hash, attempt.idempotency_key, attempt.attempt_number,
                 attempt.state.value, attempt.created_at),
            )
            self.db.commit()
        except sqlite3.IntegrityError as exc:
            self.db.rollback()
            if "idempotency_key" in str(exc):
                raise ExecutionAttemptError("idempotency_key_reused") from exc
            raise
        return attempt

    def get(self, attempt_id):
        row = self.db.execute(
            f"""SELECT attempt_id,task_id,grant_id,intent_hash,idempotency_key,attempt_number,state,
                       created_at,lease_expires_at,started_at,finished_at,
                       executor_id,executor_version,executor_identity_epoch,
                       receipt_id,error
                FROM {self.TABLE} WHERE attempt_id=?""",
            (str(attempt_id),),
        ).fetchone()
        if row is None:
            raise ExecutionAttemptError("attempt_not_found")
        try:
            state = ExecutionAttemptState(row[6])
        except ValueError as exc:
            raise ExecutionAttemptError("invalid_attempt_state") from exc
        return ExecutionAttempt(*row[:6], state, *row[7:])

    def transition(self, attempt_id, new_state, now=None, error="",
                   executor_id="", executor_version="", executor_identity_epoch=0,
                   receipt_id=""):
        try:
            new_state = ExecutionAttemptState(new_state)
        except ValueError as exc:
            raise ExecutionAttemptError("invalid_attempt_state") from exc
        current = self.get(attempt_id)
        if new_state not in _ALLOWED[current.state]:
            raise ExecutionAttemptError(
                f"invalid_transition:{current.state.value}->{new_state.value}"
            )
        when = self._now(now).isoformat()
        started_at = current.started_at
        finished_at = current.finished_at
        lease_expires_at = current.lease_expires_at
        if new_state == ExecutionAttemptState.LEASED:
            lease_expires_at = (self._now(now) + timedelta(minutes=5)).isoformat()
        if new_state == ExecutionAttemptState.RUNNING and not started_at:
            started_at = when
        if new_state in _TERMINAL:
            finished_at = when
        self.db.execute(
            f"""UPDATE {self.TABLE}
                SET state=?, lease_expires_at=?, started_at=?, finished_at=?,
                    executor_id=COALESCE(NULLIF(?,''),executor_id),
                    executor_version=COALESCE(NULLIF(?,''),executor_version),
                    executor_identity_epoch=CASE WHEN ? > 0 THEN ? ELSE executor_identity_epoch END,
                    receipt_id=COALESCE(NULLIF(?,''),receipt_id),
                    error=CASE WHEN ? <> '' THEN ? ELSE error END
                WHERE attempt_id=? AND state=?""",
            (new_state.value, lease_expires_at, started_at, finished_at,
             executor_id, executor_version, int(executor_identity_epoch),
             int(executor_identity_epoch), receipt_id, error, error,
             attempt_id, current.state.value),
        )
        if self.db.execute("SELECT changes()").fetchone()[0] != 1:
            self.db.rollback()
            raise ExecutionAttemptError("attempt_state_conflict")
        self.db.commit()
        return self.get(attempt_id)

    def find_by_idempotency_key(self, idempotency_key):
        row = self.db.execute(
            f"SELECT attempt_id FROM {self.TABLE} WHERE idempotency_key=? ORDER BY attempt_number DESC LIMIT 1",
            (str(idempotency_key),),
        ).fetchone()
        return self.get(row[0]) if row else None

    def expire_leases(self, now=None):
        point = self._now(now)
        rows = self.db.execute(
            f"""SELECT attempt_id FROM {self.TABLE}
                WHERE state='LEASED' AND lease_expires_at IS NOT NULL
                  AND lease_expires_at <= ?""",
            (point.isoformat(),),
        ).fetchall()
        expired = []
        for (attempt_id,) in rows:
            try:
                expired.append(self.transition(
                    attempt_id, ExecutionAttemptState.TIMED_OUT, now=point
                ))
            except ExecutionAttemptError:
                pass
        return expired
