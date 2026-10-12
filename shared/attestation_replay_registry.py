"""Durable replay protection with a local append-only hash-chain journal.

The journal detects accidental/tampered local history changes when compared with
its own state, but SQLite and its backups share a rollback domain. It does not
provide rollback resistance without an independently stored, authenticated
checkpoint. Legacy databases with accepted rows but no journal are rejected
rather than silently assigned a fabricated history.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Mapping

from shared.experiment_dossier import canonical_json
from shared.independent_runner_attestation import (
    IndependentRunnerAttestationError,
    verify_independent_runner_attestation,
)

_GENESIS = "0" * 64
_JOURNAL_DOMAIN = b"OWNERA-AEGISFORGE-ATTESTATION-JOURNAL-V1\x00"


class AttestationReplayRegistryError(ValueError):
    """Raised when a receipt is invalid, replayed, or cannot be recorded safely."""


def _event_hash(event: dict) -> str:
    return hashlib.sha256(_JOURNAL_DOMAIN + canonical_json(event).encode("ascii")).hexdigest()


def _ensure_schema(db: sqlite3.Connection) -> None:
    db.execute("""
        CREATE TABLE IF NOT EXISTS accepted_runner_attestations (
            provider_id TEXT NOT NULL,
            key_id TEXT NOT NULL,
            run_id TEXT NOT NULL,
            nonce TEXT NOT NULL,
            receipt_sha256 TEXT NOT NULL,
            first_seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            PRIMARY KEY (provider_id, run_id),
            UNIQUE (provider_id, nonce)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS attestation_replay_journal (
            provider_id TEXT NOT NULL,
            sequence INTEGER NOT NULL CHECK(sequence > 0),
            previous_head_sha256 TEXT NOT NULL,
            head_sha256 TEXT NOT NULL,
            run_id TEXT NOT NULL,
            nonce TEXT NOT NULL,
            receipt_sha256 TEXT NOT NULL,
            PRIMARY KEY (provider_id, sequence),
            UNIQUE (provider_id, run_id),
            UNIQUE (provider_id, nonce)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS attestation_replay_journal_state (
            provider_id TEXT PRIMARY KEY,
            sequence INTEGER NOT NULL CHECK(sequence >= 0),
            head_sha256 TEXT NOT NULL
        )
    """)


def _append_journal_event(
    db: sqlite3.Connection, *, provider_id: str, run_id: str, nonce: str, receipt_sha256: str
) -> tuple[int, str]:
    state = db.execute(
        "SELECT sequence, head_sha256 FROM attestation_replay_journal_state WHERE provider_id = ?",
        (provider_id,),
    ).fetchone()
    if state is None:
        legacy_count = db.execute(
            "SELECT COUNT(*) FROM accepted_runner_attestations WHERE provider_id = ?",
            (provider_id,),
        ).fetchone()[0]
        journal_count = db.execute(
            "SELECT COUNT(*) FROM attestation_replay_journal WHERE provider_id = ?",
            (provider_id,),
        ).fetchone()[0]
        if legacy_count or journal_count:
            raise AttestationReplayRegistryError(
                "replay_registry_legacy_state_requires_migration"
            )
        sequence, previous_head = 0, _GENESIS
    else:
        sequence, previous_head = state
        if type(sequence) is not int or sequence < 0 or not isinstance(previous_head, str):
            raise AttestationReplayRegistryError("replay_registry_journal_state_invalid")
        # Verify the persisted head against the last journal event before extending it.
        if sequence == 0:
            if previous_head != _GENESIS or db.execute(
                "SELECT 1 FROM attestation_replay_journal WHERE provider_id = ? LIMIT 1",
                (provider_id,),
            ).fetchone():
                raise AttestationReplayRegistryError("replay_registry_journal_state_corrupt")
        else:
            last = db.execute(
                """SELECT sequence, head_sha256 FROM attestation_replay_journal
                   WHERE provider_id = ? ORDER BY sequence DESC LIMIT 1""",
                (provider_id,),
            ).fetchone()
            if last != (sequence, previous_head):
                raise AttestationReplayRegistryError("replay_registry_journal_state_corrupt")

    next_sequence = sequence + 1
    event = {
        "schema_version": "evm-key-forensics-replay-event-v1",
        "provider_id": provider_id,
        "sequence": next_sequence,
        "previous_head_sha256": previous_head,
        "run_id": run_id,
        "nonce": nonce,
        "receipt_sha256": receipt_sha256,
    }
    head = _event_hash(event)
    db.execute(
        """INSERT INTO attestation_replay_journal
           (provider_id, sequence, previous_head_sha256, head_sha256, run_id, nonce, receipt_sha256)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (provider_id, next_sequence, previous_head, head, run_id, nonce, receipt_sha256),
    )
    db.execute(
        """INSERT INTO attestation_replay_journal_state(provider_id, sequence, head_sha256)
           VALUES (?, ?, ?)
           ON CONFLICT(provider_id) DO UPDATE SET sequence=excluded.sequence,
               head_sha256=excluded.head_sha256""",
        (provider_id, next_sequence, head),
    )
    return next_sequence, head


def verify_and_record_attestation(
    dossier: dict,
    envelope: dict,
    *,
    trusted_public_keys: Mapping[str, bytes],
    database_path: str | Path,
) -> dict:
    """Verify a receipt, then atomically reserve its run ID/nonce and journal it.

    Validation happens before the transaction so invalid input cannot burn a
    nonce. SQLite's IMMEDIATE transaction and unique constraints serialize
    concurrent writers. Any persistence or journal-integrity failure fails closed.
    """
    try:
        verified = verify_independent_runner_attestation(
            dossier, envelope, trusted_public_keys=trusted_public_keys
        )
    except IndependentRunnerAttestationError as exc:
        raise AttestationReplayRegistryError(f"attestation_invalid:{exc}") from exc

    provider_id = dossier["runner"]["provider_id"]
    nonce = dossier["nonce"]
    run_id = dossier["run_id"]
    key_id = verified["key_id"]
    receipt_sha256 = verified["receipt_sha256"]

    try:
        with sqlite3.connect(str(database_path), timeout=5.0, isolation_level=None) as db:
            db.execute("PRAGMA busy_timeout = 5000")
            db.execute("PRAGMA foreign_keys = ON")
            _ensure_schema(db)
            db.execute("BEGIN IMMEDIATE")
            try:
                # Check/migrate guard runs before the accepted row is inserted. The
                # journal append and replay reservation then commit as one unit.
                state = db.execute(
                    "SELECT sequence, head_sha256 FROM attestation_replay_journal_state WHERE provider_id = ?",
                    (provider_id,),
                ).fetchone()
                if state is None:
                    existing = db.execute(
                        "SELECT COUNT(*) FROM accepted_runner_attestations WHERE provider_id = ?",
                        (provider_id,),
                    ).fetchone()[0]
                    journal_rows = db.execute(
                        "SELECT COUNT(*) FROM attestation_replay_journal WHERE provider_id = ?",
                        (provider_id,),
                    ).fetchone()[0]
                    if existing or journal_rows:
                        raise AttestationReplayRegistryError(
                            "replay_registry_legacy_state_requires_migration"
                        )
                    db.execute(
                        "INSERT INTO attestation_replay_journal_state(provider_id, sequence, head_sha256) VALUES (?, 0, ?)",
                        (provider_id, _GENESIS),
                    )
                db.execute(
                    """INSERT INTO accepted_runner_attestations
                       (provider_id, key_id, run_id, nonce, receipt_sha256)
                       VALUES (?, ?, ?, ?, ?)""",
                    (provider_id, key_id, run_id, nonce, receipt_sha256),
                )
                sequence, head = _append_journal_event(
                    db, provider_id=provider_id, run_id=run_id, nonce=nonce,
                    receipt_sha256=receipt_sha256,
                )
                db.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                db.execute("ROLLBACK")
                raise AttestationReplayRegistryError(
                    "attestation_replay_detected:run_id_or_nonce_already_seen"
                ) from exc
            except Exception:
                db.execute("ROLLBACK")
                raise
    except AttestationReplayRegistryError:
        raise
    except (sqlite3.Error, OSError, ValueError) as exc:
        raise AttestationReplayRegistryError("replay_registry_unavailable_fail_closed") from exc

    result = dict(verified)
    result["replay_protection"] = "RECORDED_ONCE_IN_LOCAL_SQLITE_REGISTRY"
    result["journal"] = {
        "schema_version": "evm-key-forensics-replay-event-v1",
        "sequence": sequence,
        "head_sha256": head,
        "integrity_scope": "LOCAL_SQLITE_HASH_CHAIN_ONLY",
        "rollback_resistance": "EXTERNAL_ANCHOR_REQUIRED",
    }
    result["qualification"] = "NOT_ESTABLISHED"
    return result
