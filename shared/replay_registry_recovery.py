"""Read-only, fail-closed planning for replay registry recovery.

This module does not modify SQLite or publish an external anchor. It validates
that the local journal extends an explicitly supplied trusted anchor and that
every suffix event has a signed receipt/dossier pair that verifies under the
caller-provided trust keys. Operator confirmation and anchor CAS remain separate.
"""
from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import Mapping

from shared.attestation_replay_registry import (
    AttestationReplayRegistryError,
    _GENESIS,
    _event_hash,
)
from shared.experiment_dossier import canonical_json
from shared.independent_runner_attestation import (
    IndependentRunnerAttestationError,
    verify_independent_runner_attestation,
)


class ReplayRecoveryError(ValueError):
    """Raised when a read-only recovery plan cannot be safely constructed."""


def build_replay_recovery_plan(
    database_path: str | Path,
    *,
    provider_id: str,
    anchor_sequence: int,
    anchor_head_sha256: str,
    trusted_public_keys: Mapping[str, bytes],
) -> dict:
    """Validate a journal suffix against a trusted anchor and return a plan.

    The supplied anchor must have been read from the real external anchor store
    by the caller. This function deliberately has no anchor-store or write API.
    The returned plan is informational and must be revalidated before any CAS.
    """
    if not isinstance(provider_id, str) or not provider_id.strip():
        raise ReplayRecoveryError("recovery_provider_id_invalid")
    if type(anchor_sequence) is not int or anchor_sequence < 0:
        raise ReplayRecoveryError("recovery_anchor_sequence_invalid")
    if not isinstance(anchor_head_sha256, str) or len(anchor_head_sha256) != 64 or any(
        char not in "0123456789abcdef" for char in anchor_head_sha256
    ):
        raise ReplayRecoveryError("recovery_anchor_head_invalid")
    if anchor_sequence == 0 and anchor_head_sha256 != _GENESIS:
        raise ReplayRecoveryError("recovery_anchor_genesis_invalid")

    try:
        with sqlite3.connect(str(database_path), timeout=5.0) as db:
            db.row_factory = sqlite3.Row
            tables = {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            required = {
                "attestation_replay_journal",
                "attestation_replay_journal_state",
                "attestation_replay_evidence",
                "accepted_runner_attestations",
            }
            if not required.issubset(tables):
                raise ReplayRecoveryError("recovery_registry_schema_incomplete")
            state = db.execute(
                "SELECT sequence, head_sha256 FROM attestation_replay_journal_state WHERE provider_id=?",
                (provider_id,),
            ).fetchone()
            if state is None:
                counts = []
                for table in ("attestation_replay_journal", "attestation_replay_evidence", "accepted_runner_attestations"):
                    counts.append(db.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE provider_id=?", (provider_id,)
                    ).fetchone()[0])
                if any(counts):
                    raise ReplayRecoveryError("recovery_local_state_missing_with_existing_records")
                if anchor_sequence == 0 and anchor_head_sha256 == _GENESIS:
                    return _make_plan(provider_id, anchor_sequence, anchor_head_sha256, 0, _GENESIS, [])
                raise ReplayRecoveryError("recovery_local_state_missing_for_non_genesis_anchor")
            terminal_sequence, terminal_head = state["sequence"], state["head_sha256"]
            if type(terminal_sequence) is not int or terminal_sequence < 0:
                raise ReplayRecoveryError("recovery_local_state_invalid")
            if anchor_sequence > terminal_sequence:
                raise ReplayRecoveryError("recovery_anchor_ahead_of_local_registry")

            rows = db.execute(
                """SELECT sequence, previous_head_sha256, head_sha256, run_id, nonce, receipt_sha256
                   FROM attestation_replay_journal WHERE provider_id=? ORDER BY sequence""",
                (provider_id,),
            ).fetchall()
            evidence_rows = db.execute(
                """SELECT sequence, run_id, nonce, receipt_sha256, journal_head_sha256,
                          dossier_json, envelope_json
                   FROM attestation_replay_evidence WHERE provider_id=? ORDER BY sequence""",
                (provider_id,),
            ).fetchall()
            accepted_rows = db.execute(
                """SELECT run_id, nonce, receipt_sha256 FROM accepted_runner_attestations
                   WHERE provider_id=?""", (provider_id,),
            ).fetchall()
    except ReplayRecoveryError:
        raise
    except (sqlite3.Error, OSError) as exc:
        raise ReplayRecoveryError("recovery_registry_unavailable_fail_closed") from exc

    if len(rows) != terminal_sequence or len(evidence_rows) != terminal_sequence:
        raise ReplayRecoveryError("recovery_journal_or_evidence_count_mismatch")
    if len(accepted_rows) != terminal_sequence:
        raise ReplayRecoveryError("recovery_accepted_row_count_mismatch")

    evidence_by_sequence = {row["sequence"]: row for row in evidence_rows}
    accepted = {(row["run_id"], row["nonce"]): row["receipt_sha256"] for row in accepted_rows}
    previous = _GENESIS
    suffix = []
    observed_anchor_head = _GENESIS
    for expected_sequence, row in enumerate(rows, start=1):
        event = {
            "schema_version": "evm-key-forensics-replay-event-v1",
            "provider_id": provider_id,
            "sequence": expected_sequence,
            "previous_head_sha256": previous,
            "run_id": row["run_id"],
            "nonce": row["nonce"],
            "receipt_sha256": row["receipt_sha256"],
        }
        calculated_head = _event_hash(event)
        if (row["sequence"] != expected_sequence or
                row["previous_head_sha256"] != previous or
                row["head_sha256"] != calculated_head):
            raise ReplayRecoveryError("recovery_journal_chain_corrupt")
        if expected_sequence == anchor_sequence and calculated_head != anchor_head_sha256:
            raise ReplayRecoveryError("recovery_anchor_does_not_match_local_history")
        if expected_sequence == anchor_sequence:
            observed_anchor_head = calculated_head

        evidence = evidence_by_sequence.get(expected_sequence)
        if evidence is None or (
            evidence["run_id"] != row["run_id"] or
            evidence["nonce"] != row["nonce"] or
            evidence["receipt_sha256"] != row["receipt_sha256"] or
            evidence["journal_head_sha256"] != calculated_head
        ):
            raise ReplayRecoveryError("recovery_evidence_journal_binding_mismatch")
        if accepted.get((row["run_id"], row["nonce"])) != row["receipt_sha256"]:
            raise ReplayRecoveryError("recovery_accepted_row_binding_mismatch")

        try:
            dossier = __import__("json").loads(evidence["dossier_json"])
            envelope = __import__("json").loads(evidence["envelope_json"])
            verified = verify_independent_runner_attestation(
                dossier, envelope, trusted_public_keys=trusted_public_keys
            )
        except (ValueError, TypeError, KeyError, IndependentRunnerAttestationError) as exc:
            raise ReplayRecoveryError("recovery_signed_evidence_invalid") from exc
        if (
            dossier["runner"]["provider_id"] != provider_id or
            dossier["run_id"] != row["run_id"] or dossier["nonce"] != row["nonce"] or
            verified["receipt_sha256"] != row["receipt_sha256"]
        ):
            raise ReplayRecoveryError("recovery_signed_evidence_binding_mismatch")
        if expected_sequence > anchor_sequence:
            suffix.append({
                "sequence": expected_sequence,
                "run_id": row["run_id"],
                "nonce": row["nonce"],
                "receipt_sha256": row["receipt_sha256"],
                "journal_head_sha256": calculated_head,
                "key_id": verified["key_id"],
            })
        previous = calculated_head

    if terminal_sequence == 0 and terminal_head != _GENESIS:
        raise ReplayRecoveryError("recovery_empty_state_head_invalid")
    if previous != terminal_head:
        raise ReplayRecoveryError("recovery_terminal_state_mismatch")
    if anchor_sequence == 0:
        observed_anchor_head = _GENESIS
    if observed_anchor_head != anchor_head_sha256:
        raise ReplayRecoveryError("recovery_anchor_does_not_match_local_history")
    return _make_plan(provider_id, anchor_sequence, anchor_head_sha256,
                      terminal_sequence, terminal_head, suffix)


def _make_plan(provider_id, anchor_sequence, anchor_head, terminal_sequence, terminal_head, suffix):
    body = {
        "schema_version": "evm-key-forensics-recovery-plan-v1",
        "provider_id": provider_id,
        "anchor": {"sequence": anchor_sequence, "head_sha256": anchor_head},
        "terminal": {"sequence": terminal_sequence, "head_sha256": terminal_head},
        "suffix": suffix,
        "action": "NO_OP_ALREADY_ANCHORED" if terminal_sequence == anchor_sequence else "OPERATOR_REVIEW_REQUIRED",
        "writes_performed": False,
        "anchor_updated": False,
        "qualification": "NOT_ESTABLISHED",
    }
    digest = hashlib.sha256(b"OWNERA-AEGISFORGE-RECOVERY-PLAN-V1\x00" + canonical_json(body).encode("ascii")).hexdigest()
    return {**body, "plan_sha256": digest}


def revalidate_replay_recovery_plan(
    database_path: str | Path,
    *,
    plan: Mapping,
    provider_id: str,
    current_anchor_sequence: int,
    current_anchor_head_sha256: str,
    trusted_public_keys: Mapping[str, bytes],
) -> dict:
    """Rebuild a recovery plan against a freshly read external anchor.

    Call this immediately before presenting a plan for operator approval and
    again before any future anchor CAS. The caller must read the anchor from
    the authoritative external store; passing the values from the old plan
    does not provide freshness. This function remains read-only.
    """
    if not isinstance(plan, Mapping):
        raise ReplayRecoveryError("recovery_plan_invalid")
    if plan.get("provider_id") != provider_id:
        raise ReplayRecoveryError("recovery_plan_provider_mismatch")

    current = build_replay_recovery_plan(
        database_path,
        provider_id=provider_id,
        anchor_sequence=current_anchor_sequence,
        anchor_head_sha256=current_anchor_head_sha256,
        trusted_public_keys=trusted_public_keys,
    )
    if dict(plan) != current:
        raise ReplayRecoveryError("recovery_plan_stale_or_tampered")
    return {
        "valid": True,
        "plan_sha256": current["plan_sha256"],
        "terminal": current["terminal"],
        "writes_performed": False,
        "anchor_updated": False,
        "qualification": "NOT_ESTABLISHED",
    }
