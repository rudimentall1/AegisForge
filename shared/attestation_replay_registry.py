"""Durable local replay protection for dossier-bound lab receipts.

This registry prevents the same provider/key run ID or nonce from being accepted
more than once by this database. It does not establish provider independence,
remote freshness, or scientific validity.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Mapping

from shared.independent_runner_attestation import (
    IndependentRunnerAttestationError,
    verify_independent_runner_attestation,
)


class AttestationReplayRegistryError(ValueError):
    """Raised when a receipt is invalid, replayed, or cannot be recorded safely."""


def verify_and_record_attestation(
    dossier: dict,
    envelope: dict,
    *,
    trusted_public_keys: Mapping[str, bytes],
    database_path: str | Path,
) -> dict:
    """Verify a receipt, then atomically reserve its run ID and nonce.

    Validation happens before the transaction so invalid input cannot burn a
    nonce. SQLite's IMMEDIATE transaction and unique constraints serialize
    concurrent writers. Any persistence failure fails closed.
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
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute(
                    """INSERT INTO accepted_runner_attestations
                       (provider_id, key_id, run_id, nonce, receipt_sha256)
                       VALUES (?, ?, ?, ?, ?)""",
                    (provider_id, key_id, run_id, nonce, receipt_sha256),
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
    result["qualification"] = "NOT_ESTABLISHED"
    return result
