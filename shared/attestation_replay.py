"""Durable replay protection for verified execution attestations.

The registry records (signer_id, nonce) pairs atomically. Keep the database on
durable storage shared by all verifier workers that must enforce one replay
domain. A local SQLite file is not a distributed registry when workers use
different files or hosts.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path


class SQLiteAttestationReplayRegistry:
    """SQLite-backed, atomic nonce registry.

    Reusing a signer/nonce pair returns False. Database errors are raised so
    callers can fail closed; this class never treats an unavailable store as
    permission to accept an attestation.
    """

    def __init__(self, database_path: str | Path) -> None:
        if str(database_path) == ":memory:" or not str(database_path).strip():
            raise ValueError("replay_registry_requires_durable_database_path")
        self.database_path = str(database_path)
        with sqlite3.connect(self.database_path, timeout=10) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS consumed_attestation_nonces (
                    signer_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    consumed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (signer_id, nonce)
                )
                """
            )

    def consume(self, signer_id: str, nonce: str) -> bool:
        """Atomically consume a nonce; return False when already consumed."""
        if not isinstance(signer_id, str) or not signer_id:
            raise ValueError("replay_registry_signer_id_invalid")
        if not isinstance(nonce, str) or not nonce:
            raise ValueError("replay_registry_nonce_invalid")
        try:
            with sqlite3.connect(self.database_path, timeout=10) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO consumed_attestation_nonces (signer_id, nonce) VALUES (?, ?)",
                    (signer_id, nonce),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def consume_many(self, pairs: list[tuple[str, str]]) -> bool:
        """Atomically consume a whole attested package's nonce set.

        If any signer/nonce pair was already consumed (or is duplicated within
        this request), none of the new pairs are committed. This avoids partially
        burning later nonces when a package replay is detected partway through.
        """
        if not isinstance(pairs, list):
            raise ValueError("replay_registry_pairs_invalid")
        normalized = []
        for pair in pairs:
            if (
                not isinstance(pair, (tuple, list))
                or len(pair) != 2
            ):
                raise ValueError("replay_registry_pair_invalid")
            signer_id, nonce = pair
            if not isinstance(signer_id, str) or not signer_id:
                raise ValueError("replay_registry_signer_id_invalid")
            if not isinstance(nonce, str) or not nonce:
                raise ValueError("replay_registry_nonce_invalid")
            normalized.append((signer_id, nonce))
        if len(set(normalized)) != len(normalized):
            return False
        if not normalized:
            return True

        connection = sqlite3.connect(self.database_path, timeout=10)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.executemany(
                "INSERT INTO consumed_attestation_nonces (signer_id, nonce) VALUES (?, ?)",
                normalized,
            )
            connection.commit()
            return True
        except sqlite3.IntegrityError:
            connection.rollback()
            return False
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


def verify_execution_attestation_with_replay_protection(
    attestation: object,
    *,
    trusted_public_key_bytes: bytes,
    expected_signer_id: str,
    replay_registry: object,
    **verification_options: object,
) -> dict:
    """Verify signature/claims, then atomically consume the signed nonce.

    The registry must provide consume(signer_id, nonce) -> bool. It must be
    durable and shared across every verifier in the intended replay domain.
    Registry errors fail closed. This is separate from freshness enforcement:
    callers should also set max_age_seconds when an issuance window is needed.
    """
    from shared.execution_attestation import verify_execution_attestation

    report = verify_execution_attestation(
        attestation,
        trusted_public_key_bytes=trusted_public_key_bytes,
        expected_signer_id=expected_signer_id,
        **verification_options,
    )
    if report.get("status") != "PASS":
        report["replay_protection_verified"] = False
        return report

    claims = attestation["claims"]
    consume = getattr(replay_registry, "consume", None)
    if not callable(consume):
        return {
            **report,
            "status": "FAIL",
            "replay_protection_verified": False,
            "errors": [*report.get("errors", []), "attestation_replay_registry_invalid"],
        }
    try:
        consumed = consume(claims["signer_id"], claims["nonce"])
    except Exception:
        return {
            **report,
            "status": "FAIL",
            "replay_protection_verified": False,
            "errors": [*report.get("errors", []), "attestation_replay_registry_unavailable"],
        }
    if consumed is not True:
        return {
            **report,
            "status": "FAIL",
            "replay_protection_verified": False,
            "errors": [*report.get("errors", []), "attestation_replay_detected"],
        }
    return {**report, "replay_protection_verified": True}


def verify_bundle_execution_attestation_with_replay_protection(
    bundle_bytes: bytes,
    attestation: object,
    *,
    trusted_public_key_bytes: bytes,
    expected_signer_id: str,
    replay_registry: object,
    **verification_options: object,
) -> dict:
    """Verify bundle integrity and record-bound attestation before consuming nonce."""
    from shared.execution_attestation import verify_bundle_execution_attestation

    report = verify_bundle_execution_attestation(
        bundle_bytes,
        attestation,
        trusted_public_key_bytes=trusted_public_key_bytes,
        expected_signer_id=expected_signer_id,
        **verification_options,
    )
    if report.get("status") != "PASS":
        report["replay_protection_verified"] = False
        return report

    claims = attestation["claims"]
    consume = getattr(replay_registry, "consume", None)
    if not callable(consume):
        return {
            **report,
            "status": "FAIL",
            "replay_protection_verified": False,
            "errors": [*report.get("errors", []), "attestation_replay_registry_invalid"],
        }
    try:
        consumed = consume(claims["signer_id"], claims["nonce"])
    except Exception:
        return {
            **report,
            "status": "FAIL",
            "replay_protection_verified": False,
            "errors": [*report.get("errors", []), "attestation_replay_registry_unavailable"],
        }
    if consumed is not True:
        return {
            **report,
            "status": "FAIL",
            "replay_protection_verified": False,
            "errors": [*report.get("errors", []), "attestation_replay_detected"],
        }
    return {**report, "replay_protection_verified": True}
