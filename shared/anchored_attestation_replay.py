"""Strict adapter for replay registration backed by an independent monotonic anchor.

The anchor service must live outside the SQLite backup/restore domain and provide
linearizable compare-and-set semantics. This adapter deliberately fails closed
when local and external state differ. A failed publish can leave a local receipt
recorded but unacknowledged; callers must treat the operation as failed and
reconcile out of band before accepting more receipts.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Mapping, Protocol

from shared.attestation_replay_registry import (
    AttestationReplayRegistryError,
    verify_and_record_attestation,
)

_GENESIS = "0" * 64


class ReplayAnchorUnavailable(AttestationReplayRegistryError):
    """Raised when external monotonic state cannot be read or updated safely."""


class ReplayAnchorStore(Protocol):
    """Minimal contract for a separately protected, linearizable anchor store."""

    def get_anchor(self, provider_id: str) -> Mapping[str, object]:
        """Return provider_id, sequence, and head_sha256 from durable external state."""

    def compare_and_set_anchor(
        self,
        provider_id: str,
        *,
        expected_sequence: int,
        expected_head_sha256: str,
        new_sequence: int,
        new_head_sha256: str,
    ) -> bool:
        """Atomically replace the exact expected anchor; return False on conflict."""


def _local_state(database_path: str | Path, provider_id: str) -> tuple[int, str]:
    path = Path(database_path)
    if not path.exists():
        return 0, _GENESIS
    try:
        with sqlite3.connect(str(path), timeout=5.0) as db:
            # Read schema, journal head, and legacy-row counts from one SQLite
            # snapshot. Separate autocommit SELECTs can straddle another writer's
            # commit and falsely observe accepted rows without their journal state.
            db.execute("BEGIN")
            tables = {
                row[0]
                for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            if "attestation_replay_journal_state" not in tables:
                if "accepted_runner_attestations" in tables:
                    count = db.execute(
                        "SELECT COUNT(*) FROM accepted_runner_attestations WHERE provider_id = ?",
                        (provider_id,),
                    ).fetchone()[0]
                    if count:
                        raise AttestationReplayRegistryError(
                            "replay_registry_legacy_state_requires_migration"
                        )
                return 0, _GENESIS
            row = db.execute(
                "SELECT sequence, head_sha256 FROM attestation_replay_journal_state WHERE provider_id = ?",
                (provider_id,),
            ).fetchone()
            if row is None:
                if "accepted_runner_attestations" in tables:
                    count = db.execute(
                        "SELECT COUNT(*) FROM accepted_runner_attestations WHERE provider_id = ?",
                        (provider_id,),
                    ).fetchone()[0]
                    if count:
                        raise AttestationReplayRegistryError(
                            "replay_registry_legacy_state_requires_migration"
                        )
                return 0, _GENESIS
            sequence, head = row
            if type(sequence) is not int or sequence < 0 or not isinstance(head, str):
                raise AttestationReplayRegistryError("replay_registry_journal_state_invalid")
            return sequence, head
    except AttestationReplayRegistryError:
        raise
    except (sqlite3.Error, OSError) as exc:
        raise ReplayAnchorUnavailable("external_anchor_local_state_unavailable") from exc


def _validate_anchor(
    anchor: Mapping[str, object], *, provider_id: str
) -> tuple[int, str]:
    if not isinstance(anchor, Mapping) or set(anchor) != {
        "provider_id", "sequence", "head_sha256"
    }:
        raise ReplayAnchorUnavailable("external_anchor_envelope_invalid")
    sequence = anchor.get("sequence")
    head = anchor.get("head_sha256")
    if anchor.get("provider_id") != provider_id:
        raise ReplayAnchorUnavailable("external_anchor_provider_mismatch")
    if type(sequence) is not int or sequence < 0:
        raise ReplayAnchorUnavailable("external_anchor_sequence_invalid")
    if not isinstance(head, str) or len(head) != 64 or any(
        char not in "0123456789abcdef" for char in head
    ):
        raise ReplayAnchorUnavailable("external_anchor_head_invalid")
    if sequence == 0 and head != _GENESIS:
        raise ReplayAnchorUnavailable("external_anchor_genesis_invalid")
    return sequence, head


def verify_and_record_attestation_anchored(
    dossier: dict,
    envelope: dict,
    *,
    trusted_public_keys: Mapping[str, bytes],
    database_path: str | Path,
    anchor_store: ReplayAnchorStore,
) -> dict:
    """Record an attestation only while local and external heads agree exactly.

    This is the strict integration path. The anchor store must be independently
    protected and linearizable. It must be provisioned with an explicit genesis
    anchor for each provider. There is intentionally no local-only fallback.

    If the post-commit compare-and-set fails, the local receipt may already be
    recorded. The function raises and refuses to report success; subsequent
    strict calls fail closed on the state mismatch until an operator reconciles
    the one-step-or-more unanchored suffix. Do not execute a lab result based on
    a raised call.
    """
    provider_id = dossier.get("runner", {}).get("provider_id")
    if not isinstance(provider_id, str) or not provider_id:
        raise AttestationReplayRegistryError("attestation_provider_id_invalid")
    try:
        external = anchor_store.get_anchor(provider_id)
    except Exception as exc:
        raise ReplayAnchorUnavailable("external_anchor_unavailable_fail_closed") from exc
    expected_sequence, expected_head = _validate_anchor(external, provider_id=provider_id)
    local_sequence, local_head = _local_state(database_path, provider_id)
    if (local_sequence, local_head) != (expected_sequence, expected_head):
        raise ReplayAnchorUnavailable("local_registry_differs_from_external_anchor")

    result = verify_and_record_attestation(
        dossier,
        envelope,
        trusted_public_keys=trusted_public_keys,
        database_path=database_path,
    )
    journal = result.get("journal")
    if not isinstance(journal, dict):
        raise ReplayAnchorUnavailable("local_registry_journal_missing_after_record")
    new_sequence = journal.get("sequence")
    new_head = journal.get("head_sha256")
    if new_sequence != expected_sequence + 1 or not isinstance(new_head, str):
        raise ReplayAnchorUnavailable("local_registry_unexpected_successor")
    try:
        published = anchor_store.compare_and_set_anchor(
            provider_id,
            expected_sequence=expected_sequence,
            expected_head_sha256=expected_head,
            new_sequence=new_sequence,
            new_head_sha256=new_head,
        )
    except Exception as exc:
        raise ReplayAnchorUnavailable("external_anchor_publish_failed_reconcile_required") from exc
    if published is not True:
        raise ReplayAnchorUnavailable("external_anchor_compare_and_set_conflict_reconcile_required")

    anchored = dict(result)
    anchored["replay_protection"] = "LOCAL_REGISTRY_AND_EXTERNAL_MONOTONIC_ANCHOR"
    anchored["journal"] = {
        **journal,
        "integrity_scope": "LOCAL_HASH_CHAIN_VERIFIED_AGAINST_EXTERNAL_ANCHOR",
        "rollback_resistance": "EXTERNAL_ANCHOR_CONFIRMED_FOR_RETURNED_HEAD",
    }
    return anchored
