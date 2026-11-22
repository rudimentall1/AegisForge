"""Append-only records for explicitly admitted on-chain reproduction rounds.

This module persists execution intent and evidence identity only. It does not
execute harnesses, invoke Foundry, perform RPC calls, or submit transactions.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
import sqlite3
from typing import Any

from shared.onchain_execution_admission import (
    AdmittedOnchainExecution,
    OnchainExecutionAdmissionError,
    OnchainExecutionRequest,
    admit_onchain_execution,
)
from shared.onchain_verification_store import OnchainVerificationStore
from shared.queue import TaskQueue


MAX_HARNESS_ARTIFACT_BYTES = 256 * 1024
MAX_HARNESS_BUNDLE_BYTES = 512 * 1024
_HASH32_RE = re.compile(r"^[0-9a-f]{64}$")
_FINAL_STATUSES = {"INCONCLUSIVE", "SOURCE_ONLY", "NOT_REPRODUCED", "REPRODUCED"}


class OnchainExecutionRoundError(ValueError):
    """Invalid on-chain execution round or immutable outcome."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _validate_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or not _HASH32_RE.fullmatch(value):
        raise OnchainExecutionRoundError(f"{field}_invalid")
    return value


@dataclass(frozen=True, slots=True)
class OnchainHarnessBundle:
    """Three distinct, bounded Solidity harness artifacts; never executed here."""

    primary_harness: str
    positive_control: str
    negative_control: str

    def __post_init__(self) -> None:
        values = {
            "primary_harness": self.primary_harness,
            "positive_control": self.positive_control,
            "negative_control": self.negative_control,
        }
        for name, value in values.items():
            if not isinstance(value, str) or not value.strip():
                raise OnchainExecutionRoundError(f"{name}_required")
            try:
                encoded = value.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise OnchainExecutionRoundError(f"{name}_encoding_invalid") from exc
            if len(encoded) > MAX_HARNESS_ARTIFACT_BYTES:
                raise OnchainExecutionRoundError("harness_artifact_too_large")
        if len(set(values.values())) != len(values):
            raise OnchainExecutionRoundError("harness_controls_must_be_distinct")
        if len(_canonical_json(values).encode("utf-8")) > MAX_HARNESS_BUNDLE_BYTES:
            raise OnchainExecutionRoundError("harness_bundle_too_large")

    def to_dict(self) -> dict[str, str]:
        return {
            "primary_harness": self.primary_harness,
            "positive_control": self.positive_control,
            "negative_control": self.negative_control,
        }

    @property
    def sha256(self) -> str:
        return hashlib.sha256(_canonical_json(self.to_dict()).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class OnchainExecutionRoundRecord:
    round_id: str
    case_id: str
    target_id: str
    block_hash: str
    verification_id: str
    authorization_reference: str
    profile: str
    harness_sha256: str
    harness_bundle: OnchainHarnessBundle
    status: str
    evidence_sha256: str | None
    created_at: str
    confirmed: bool = False
    evidence_scope: str = "LOCAL_HARNESS_ONLY"


class OnchainExecutionRoundStore:
    """SQLite append-only identity and outcome ledger for on-chain execution rounds."""

    def __init__(self, db: sqlite3.Connection):
        if not isinstance(db, sqlite3.Connection):
            raise OnchainExecutionRoundError("sqlite_connection_required")
        self.db = db
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS onchain_execution_rounds (
                round_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                block_hash TEXT NOT NULL,
                verification_id TEXT NOT NULL,
                authorization_reference TEXT NOT NULL,
                profile TEXT NOT NULL,
                harness_sha256 TEXT NOT NULL,
                harness_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS onchain_execution_round_events (
                event_id TEXT PRIMARY KEY,
                round_id TEXT NOT NULL,
                status TEXT NOT NULL,
                evidence_sha256 TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(round_id) REFERENCES onchain_execution_rounds(round_id)
            )
        """)
        self.db.execute("""
            CREATE INDEX IF NOT EXISTS idx_onchain_execution_round_events
            ON onchain_execution_round_events(round_id, created_at, event_id)
        """)
        self.db.execute("""
            CREATE TRIGGER IF NOT EXISTS onchain_execution_rounds_no_update
            BEFORE UPDATE ON onchain_execution_rounds
            BEGIN
                SELECT RAISE(ABORT, 'onchain_execution_round_immutable');
            END
        """)
        self.db.execute("""
            CREATE TRIGGER IF NOT EXISTS onchain_execution_rounds_no_delete
            BEFORE DELETE ON onchain_execution_rounds
            BEGIN
                SELECT RAISE(ABORT, 'onchain_execution_round_immutable');
            END
        """)
        self.db.execute("""
            CREATE TRIGGER IF NOT EXISTS onchain_execution_round_events_no_update
            BEFORE UPDATE ON onchain_execution_round_events
            BEGIN
                SELECT RAISE(ABORT, 'onchain_execution_round_event_immutable');
            END
        """)
        self.db.execute("""
            CREATE TRIGGER IF NOT EXISTS onchain_execution_round_events_no_delete
            BEFORE DELETE ON onchain_execution_round_events
            BEGIN
                SELECT RAISE(ABORT, 'onchain_execution_round_event_immutable');
            END
        """)
        self.db.commit()

    def create_round(
        self,
        queue: TaskQueue,
        verification_store: OnchainVerificationStore,
        request: OnchainExecutionRequest,
        harness_bundle: OnchainHarnessBundle,
    ) -> OnchainExecutionRoundRecord:
        """Re-admit against persisted state, then persist an immutable NOT_RUN round."""
        if not isinstance(queue, TaskQueue):
            raise OnchainExecutionRoundError("task_queue_required")
        if not isinstance(verification_store, OnchainVerificationStore):
            raise OnchainExecutionRoundError("verification_store_required")
        if queue.db is not self.db or verification_store.db is not self.db:
            raise OnchainExecutionRoundError("shared_database_connection_required")
        if not isinstance(harness_bundle, OnchainHarnessBundle):
            raise OnchainExecutionRoundError("typed_harness_bundle_required")

        try:
            admitted: AdmittedOnchainExecution = admit_onchain_execution(
                queue, verification_store, request
            )
        except OnchainExecutionAdmissionError:
            raise

        identity = {
            "case_id": admitted.case.case_id,
            "target_id": admitted.target.target_id,
            "block_hash": admitted.target.block_hash,
            "verification_id": admitted.verification.verification_id,
            "authorization_reference": admitted.case.authorization_reference,
            "profile": admitted.profile.value,
            "harness_sha256": harness_bundle.sha256,
        }
        round_id = hashlib.sha256(_canonical_json(identity).encode("utf-8")).hexdigest()
        harness_json = _canonical_json(harness_bundle.to_dict())
        now = datetime.now(timezone.utc).isoformat()

        try:
            self.db.execute("BEGIN IMMEDIATE")
            latest = verification_store.latest_for_target(admitted.target.target_id)
            if latest is None or latest.verification_id != admitted.verification.verification_id:
                raise OnchainExecutionRoundError("verification_record_not_latest")
            if latest.status != "VERIFIED":
                raise OnchainExecutionRoundError("verification_status_not_verified")
            self.db.execute(
                """
                INSERT OR IGNORE INTO onchain_execution_rounds
                    (round_id, case_id, target_id, block_hash, verification_id,
                     authorization_reference, profile, harness_sha256, harness_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    round_id,
                    admitted.case.case_id,
                    admitted.target.target_id,
                    admitted.target.block_hash,
                    admitted.verification.verification_id,
                    admitted.case.authorization_reference,
                    admitted.profile.value,
                    harness_bundle.sha256,
                    harness_json,
                    now,
                ),
            )
            persisted = self.db.execute(
                """
                SELECT case_id, target_id, block_hash, verification_id,
                       authorization_reference, profile, harness_sha256, harness_json
                FROM onchain_execution_rounds WHERE round_id = ?
                """,
                (round_id,),
            ).fetchone()
            expected = (
                admitted.case.case_id,
                admitted.target.target_id,
                admitted.target.block_hash,
                admitted.verification.verification_id,
                admitted.case.authorization_reference,
                admitted.profile.value,
                harness_bundle.sha256,
                harness_json,
            )
            if persisted != expected:
                raise OnchainExecutionRoundError("round_identity_collision")
            event_id = hashlib.sha256(f"{round_id}:NOT_RUN".encode("utf-8")).hexdigest()
            self.db.execute(
                """
                INSERT OR IGNORE INTO onchain_execution_round_events
                    (event_id, round_id, status, evidence_sha256, created_at)
                VALUES (?, ?, 'NOT_RUN', NULL, ?)
                """,
                (event_id, round_id, now),
            )
            self.db.commit()
        except Exception:
            if self.db.in_transaction:
                self.db.rollback()
            raise

        record = self.get_round(round_id)
        if record is None:
            raise OnchainExecutionRoundError("round_persistence_failed")
        return record

    def record_outcome(
        self,
        round_id: str,
        status: str,
        evidence_sha256: str,
    ) -> OnchainExecutionRoundRecord:
        """Append one terminal assessment; a local reproduction is never 'confirmed'."""
        if not isinstance(round_id, str) or not _HASH32_RE.fullmatch(round_id):
            raise OnchainExecutionRoundError("round_id_invalid")
        if status not in _FINAL_STATUSES:
            raise OnchainExecutionRoundError("round_outcome_status_invalid")
        digest = _validate_digest(evidence_sha256, "round_evidence_sha256")

        try:
            self.db.execute("BEGIN IMMEDIATE")
            exists = self.db.execute(
                "SELECT 1 FROM onchain_execution_rounds WHERE round_id = ?",
                (round_id,),
            ).fetchone()
            if exists is None:
                raise OnchainExecutionRoundError("round_not_found")
            latest = self.db.execute(
                """
                SELECT status, evidence_sha256 FROM onchain_execution_round_events
                WHERE round_id = ? ORDER BY rowid DESC LIMIT 1
                """,
                (round_id,),
            ).fetchone()
            if latest is None:
                raise OnchainExecutionRoundError("round_initial_status_missing")
            if latest[0] == status and latest[1] == digest:
                self.db.commit()
                record = self.get_round(round_id)
                if record is None:
                    raise OnchainExecutionRoundError("round_not_found")
                return record
            if latest[0] != "NOT_RUN":
                raise OnchainExecutionRoundError("round_outcome_already_recorded")
            event_id = hashlib.sha256(
                f"{round_id}:{status}:{digest}".encode("utf-8")
            ).hexdigest()
            self.db.execute(
                """
                INSERT INTO onchain_execution_round_events
                    (event_id, round_id, status, evidence_sha256, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (event_id, round_id, status, digest, datetime.now(timezone.utc).isoformat()),
            )
            self.db.commit()
        except Exception:
            if self.db.in_transaction:
                self.db.rollback()
            raise

        record = self.get_round(round_id)
        if record is None:
            raise OnchainExecutionRoundError("round_persistence_failed")
        return record

    def get_round(self, round_id: str) -> OnchainExecutionRoundRecord | None:
        row = self.db.execute(
            """
            SELECT round_id, case_id, target_id, block_hash, verification_id,
                   authorization_reference, profile, harness_sha256, harness_json, created_at
            FROM onchain_execution_rounds WHERE round_id = ?
            """,
            (round_id,),
        ).fetchone()
        if row is None:
            return None
        event = self.db.execute(
            """
            SELECT status, evidence_sha256 FROM onchain_execution_round_events
            WHERE round_id = ? ORDER BY rowid DESC LIMIT 1
            """,
            (round_id,),
        ).fetchone()
        if event is None:
            raise OnchainExecutionRoundError("round_initial_status_missing")
        try:
            harness_payload = json.loads(row[8])
            bundle = OnchainHarnessBundle(**harness_payload)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise OnchainExecutionRoundError("persisted_harness_bundle_invalid") from exc
        if bundle.sha256 != row[7]:
            raise OnchainExecutionRoundError("persisted_harness_digest_mismatch")
        return OnchainExecutionRoundRecord(
            round_id=row[0],
            case_id=row[1],
            target_id=row[2],
            block_hash=row[3],
            verification_id=row[4],
            authorization_reference=row[5],
            profile=row[6],
            harness_sha256=row[7],
            harness_bundle=bundle,
            status=event[0],
            evidence_sha256=event[1],
            created_at=row[9],
        )

    def count(self) -> int:
        return int(self.db.execute("SELECT COUNT(*) FROM onchain_execution_rounds").fetchone()[0])
