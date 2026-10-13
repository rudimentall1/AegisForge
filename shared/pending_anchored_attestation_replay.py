"""Pending-first replay registration prototype for an external monotonic anchor.

Unlike the legacy adapter, this module does not reserve accepted replay state
until external CAS has confirmed the exact candidate head. It is a lab protocol
prototype; qualification remains NOT_ESTABLISHED.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Mapping

from shared.anchored_attestation_replay import (
    ReplayAnchorStore,
    ReplayAnchorUnavailable,
    _GENESIS,
    _local_state,
    _validate_anchor,
)
from shared.attestation_replay_registry import (
    AttestationReplayRegistryError,
    _event_hash,
    _ensure_schema,
    verify_and_record_attestation,
)
from shared.experiment_dossier import canonical_json
from shared.replay_registry_recovery import build_replay_recovery_plan
from shared.independent_runner_attestation import (
    IndependentRunnerAttestationError,
    verify_independent_runner_attestation,
)

_PENDING_SCHEMA = "pending-anchored-replay-v1"


def _ensure_pending_schema(db: sqlite3.Connection) -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS pending_anchored_replay (
        candidate_id TEXT PRIMARY KEY,
        provider_id TEXT NOT NULL,
        run_id TEXT NOT NULL,
        nonce TEXT NOT NULL,
        key_id TEXT NOT NULL,
        receipt_sha256 TEXT NOT NULL,
        expected_sequence INTEGER NOT NULL,
        expected_head_sha256 TEXT NOT NULL,
        candidate_sequence INTEGER NOT NULL,
        candidate_head_sha256 TEXT NOT NULL,
        dossier_json TEXT NOT NULL,
        envelope_json TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('PREPARED','CONFLICT','FINALIZED')),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    )""")


def _candidate(dossier: dict, verified: dict, prior_sequence: int, prior_head: str) -> tuple[dict, str]:
    provider_id = dossier["runner"]["provider_id"]
    sequence = prior_sequence + 1
    event = {
        "schema_version": "evm-key-forensics-replay-event-v1",
        "provider_id": provider_id,
        "sequence": sequence,
        "previous_head_sha256": prior_head,
        "run_id": dossier["run_id"],
        "nonce": dossier["nonce"],
        "receipt_sha256": verified["receipt_sha256"],
    }
    return event, _event_hash(event)


def _read_anchor(anchor_store: ReplayAnchorStore, provider_id: str) -> tuple[int, str]:
    try:
        anchor = anchor_store.get_anchor(provider_id)
    except Exception as exc:
        raise ReplayAnchorUnavailable("external_anchor_unavailable_fail_closed") from exc
    return _validate_anchor(anchor, provider_id=provider_id)


def _persist_pending(
    database_path: str | Path,
    *,
    candidate_id: str,
    dossier: dict,
    envelope: dict,
    verified: dict,
    prior_sequence: int,
    prior_head: str,
    candidate_sequence: int,
    candidate_head: str,
) -> None:
    provider_id = dossier["runner"]["provider_id"]
    try:
        with sqlite3.connect(str(database_path), timeout=5.0, isolation_level=None) as db:
            db.execute("PRAGMA busy_timeout=5000")
            _ensure_pending_schema(db)
            _ensure_schema(db)
            db.execute("BEGIN IMMEDIATE")
            try:
                current = db.execute(
                    "SELECT sequence, head_sha256 FROM attestation_replay_journal_state WHERE provider_id=?",
                    (provider_id,),
                ).fetchone()
                if current is None:
                    # Never anchor a fresh candidate for a provider whose legacy
                    # accepted state or journal exists without a matching head. The
                    # legacy adapter deliberately requires explicit migration here.
                    accepted_count = db.execute(
                        "SELECT COUNT(*) FROM accepted_runner_attestations WHERE provider_id=?",
                        (provider_id,),
                    ).fetchone()[0]
                    journal_count = db.execute(
                        "SELECT COUNT(*) FROM attestation_replay_journal WHERE provider_id=?",
                        (provider_id,),
                    ).fetchone()[0]
                    if accepted_count or journal_count:
                        raise AttestationReplayRegistryError(
                            "replay_registry_legacy_state_requires_migration"
                        )
                    current = (0, _GENESIS)
                if current != (prior_sequence, prior_head):
                    raise ReplayAnchorUnavailable("local_registry_differs_from_external_anchor")
                accepted = db.execute(
                    "SELECT 1 FROM accepted_runner_attestations WHERE provider_id=? AND (run_id=? OR nonce=?)",
                    (provider_id, dossier["run_id"], dossier["nonce"]),
                ).fetchone()
                if accepted:
                    raise AttestationReplayRegistryError("attestation_replay_detected:run_id_or_nonce_already_seen")
                existing = db.execute(
                    "SELECT candidate_head_sha256, status FROM pending_anchored_replay WHERE candidate_id=?",
                    (candidate_id,),
                ).fetchone()
                if existing:
                    if existing[0] != candidate_head:
                        raise AttestationReplayRegistryError("pending_candidate_id_collision")
                    if existing[1] == "CONFLICT":
                        raise ReplayAnchorUnavailable("pending_candidate_conflict_requires_review")
                    db.execute("COMMIT")
                    return
                db.execute("""INSERT INTO pending_anchored_replay
                    (candidate_id, provider_id, run_id, nonce, key_id, receipt_sha256,
                     expected_sequence, expected_head_sha256, candidate_sequence,
                     candidate_head_sha256, dossier_json, envelope_json, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PREPARED')""",
                    (candidate_id, provider_id, dossier["run_id"], dossier["nonce"],
                     verified["key_id"], verified["receipt_sha256"], prior_sequence,
                     prior_head, candidate_sequence, candidate_head, canonical_json(dossier),
                     canonical_json(envelope)))
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
    except (AttestationReplayRegistryError, ReplayAnchorUnavailable):
        raise
    except (sqlite3.Error, OSError, ValueError) as exc:
        raise ReplayAnchorUnavailable("pending_registry_unavailable_fail_closed") from exc


def _finalize_pending(
    database_path: str | Path,
    *,
    candidate_id: str,
    trusted_public_keys: Mapping[str, bytes],
) -> dict:
    try:
        with sqlite3.connect(str(database_path), timeout=5.0) as db:
            row = db.execute("""SELECT provider_id, run_id, nonce, receipt_sha256,
                expected_sequence, expected_head_sha256, candidate_sequence,
                candidate_head_sha256, dossier_json, envelope_json, status
                FROM pending_anchored_replay WHERE candidate_id=?""", (candidate_id,)).fetchone()
    except sqlite3.Error as exc:
        raise ReplayAnchorUnavailable("pending_registry_unavailable_fail_closed") from exc
    if row is None:
        raise ReplayAnchorUnavailable("pending_candidate_missing")
    (provider_id, run_id, nonce, receipt_sha, prior_sequence, prior_head,
     candidate_sequence, candidate_head, dossier_json, envelope_json, status) = row
    if status == "CONFLICT":
        raise ReplayAnchorUnavailable("pending_candidate_conflict_requires_review")
    if status not in ("PREPARED", "FINALIZED"):
        raise ReplayAnchorUnavailable("pending_candidate_status_invalid")
    try:
        dossier = json.loads(dossier_json)
        envelope = json.loads(envelope_json)
        verified = verify_independent_runner_attestation(
            dossier, envelope, trusted_public_keys=trusted_public_keys
        )
    except (ValueError, TypeError, KeyError, AttributeError, IndexError) as exc:
        raise ReplayAnchorUnavailable("pending_evidence_reverification_failed") from exc
    if (dossier.get("runner", {}).get("provider_id"), dossier.get("run_id"), dossier.get("nonce"),
        verified.get("receipt_sha256")) != (provider_id, run_id, nonce, receipt_sha):
        raise ReplayAnchorUnavailable("pending_evidence_binding_mismatch")
    event, recomputed_head = _candidate(dossier, verified, prior_sequence, prior_head)
    if event["sequence"] != candidate_sequence or recomputed_head != candidate_head:
        raise ReplayAnchorUnavailable("pending_candidate_hash_mismatch")

    # If a previous attempt committed SQLite but crashed before marking FINALIZED,
    # accept only the exact already-anchored candidate head and evidence row.
    local_sequence, local_head = _local_state(database_path, provider_id)
    if (local_sequence, local_head) == (candidate_sequence, candidate_head):
        build_replay_recovery_plan(
            database_path, provider_id=provider_id, anchor_sequence=candidate_sequence,
            anchor_head_sha256=candidate_head, trusted_public_keys=trusted_public_keys,
        )
        with sqlite3.connect(str(database_path), timeout=5.0) as db:
            evidence = db.execute("""SELECT 1 FROM attestation_replay_evidence
                WHERE provider_id=? AND sequence=? AND run_id=? AND nonce=?
                AND receipt_sha256=? AND journal_head_sha256=?""",
                (provider_id, candidate_sequence, run_id, nonce, receipt_sha, candidate_head)).fetchone()
            if not evidence:
                raise ReplayAnchorUnavailable("anchored_candidate_local_evidence_missing")
            db.execute("UPDATE pending_anchored_replay SET status='FINALIZED' WHERE candidate_id=?", (candidate_id,))
        return {"valid": True, "recovered": True, "journal": {
            "sequence": candidate_sequence, "head_sha256": candidate_head,
            "integrity_scope": "LOCAL_HASH_CHAIN_VERIFIED_AGAINST_EXTERNAL_ANCHOR",
            "rollback_resistance": "HISTORICALLY_ANCHORED_CANDIDATE_HEAD_CONFIRMED"},
            "replay_protection": "LOCAL_REGISTRY_AND_EXTERNAL_MONOTONIC_ANCHOR",
            "qualification": "NOT_ESTABLISHED"}

    if (local_sequence, local_head) != (prior_sequence, prior_head):
        raise ReplayAnchorUnavailable("local_registry_differs_from_pending_prior_anchor")
    try:
        result = verify_and_record_attestation(
            dossier,
            envelope,
            trusted_public_keys=trusted_public_keys,
            database_path=database_path,
            expected_journal_state=(prior_sequence, prior_head),
        )
    except AttestationReplayRegistryError as exc:
        # Two recoverers can both observe the prior local head before either
        # finalizes. If the other recoverer committed this exact candidate,
        # re-enter the idempotent already-committed path. Do not suppress a
        # replay conflict unless the durable journal now matches this candidate.
        current_sequence, current_head = _local_state(database_path, provider_id)
        if (current_sequence, current_head) != (candidate_sequence, candidate_head):
            raise
        return _finalize_pending(
            database_path, candidate_id=candidate_id,
            trusted_public_keys=trusted_public_keys,
        )
    journal = result.get("journal", {})
    if (journal.get("sequence"), journal.get("head_sha256")) != (candidate_sequence, candidate_head):
        raise ReplayAnchorUnavailable("finalized_journal_does_not_match_anchored_candidate")
    with sqlite3.connect(str(database_path), timeout=5.0) as db:
        db.execute("UPDATE pending_anchored_replay SET status='FINALIZED' WHERE candidate_id=?", (candidate_id,))
    result["replay_protection"] = "LOCAL_REGISTRY_AND_EXTERNAL_MONOTONIC_ANCHOR"
    result["journal"] = {**journal,
        "integrity_scope": "LOCAL_HASH_CHAIN_VERIFIED_AGAINST_EXTERNAL_ANCHOR",
        "rollback_resistance": "HISTORICALLY_ANCHORED_CANDIDATE_HEAD_CONFIRMED"}
    result["qualification"] = "NOT_ESTABLISHED"
    return result


def verify_and_record_attestation_pending_anchored(
    dossier: dict,
    envelope: dict,
    *,
    trusted_public_keys: Mapping[str, bytes],
    database_path: str | Path,
    anchor_store: ReplayAnchorStore,
) -> dict:
    """Stage evidence, anchor its exact candidate, then finalize local acceptance."""
    if not isinstance(dossier, dict) or not isinstance(envelope, dict):
        raise AttestationReplayRegistryError("attestation_payload_invalid")
    runner = dossier.get("runner")
    if not isinstance(runner, dict):
        raise AttestationReplayRegistryError("attestation_provider_id_invalid")
    provider_id = runner.get("provider_id")
    if not isinstance(provider_id, str) or not provider_id:
        raise AttestationReplayRegistryError("attestation_provider_id_invalid")
    try:
        verified = verify_independent_runner_attestation(
            dossier, envelope, trusted_public_keys=trusted_public_keys
        )
    except (ValueError, TypeError, KeyError, AttributeError, IndexError) as exc:
        raise AttestationReplayRegistryError(f"attestation_invalid:{exc}") from exc
    prior_sequence, prior_head = _read_anchor(anchor_store, provider_id)
    local_sequence, local_head = _local_state(database_path, provider_id)
    if (local_sequence, local_head) != (prior_sequence, prior_head):
        raise ReplayAnchorUnavailable("local_registry_differs_from_external_anchor")
    event, candidate_head = _candidate(dossier, verified, prior_sequence, prior_head)
    candidate_sequence = event["sequence"]
    candidate_id = hashlib.sha256(
        b"OWNERA-AEGISFORGE-PENDING-REPLAY-V1\x00" +
        canonical_json({"event": event, "dossier": dossier, "envelope": envelope}).encode("ascii")
    ).hexdigest()
    _persist_pending(database_path, candidate_id=candidate_id, dossier=dossier,
        envelope=envelope, verified=verified, prior_sequence=prior_sequence,
        prior_head=prior_head, candidate_sequence=candidate_sequence,
        candidate_head=candidate_head)

    # Re-read before CAS to avoid attempting a candidate against a visibly stale anchor.
    current_sequence, current_head = _read_anchor(anchor_store, provider_id)
    if (current_sequence, current_head) == (candidate_sequence, candidate_head):
        # A previous attempt may have advanced the anchor and died before finalization.
        pass
    elif (current_sequence, current_head) == (prior_sequence, prior_head):
        try:
            published = anchor_store.compare_and_set_anchor(
                provider_id, expected_sequence=prior_sequence, expected_head_sha256=prior_head,
                new_sequence=candidate_sequence, new_head_sha256=candidate_head)
        except Exception as exc:
            # Unknown outcome: only exact authoritative candidate confirmation allows recovery.
            try:
                observed_sequence, observed_head = _read_anchor(anchor_store, provider_id)
            except Exception:
                raise ReplayAnchorUnavailable("external_anchor_publish_outcome_unknown") from exc
            if (observed_sequence, observed_head) != (candidate_sequence, candidate_head):
                raise ReplayAnchorUnavailable("external_anchor_publish_outcome_unknown") from exc
        else:
            if published is not True:
                try:
                    observed_sequence, observed_head = _read_anchor(anchor_store, provider_id)
                except Exception as exc:
                    raise ReplayAnchorUnavailable("external_anchor_conflict_outcome_unknown") from exc
                if (observed_sequence, observed_head) != (candidate_sequence, candidate_head):
                    with sqlite3.connect(str(database_path), timeout=5.0) as db:
                        db.execute("UPDATE pending_anchored_replay SET status='CONFLICT' WHERE candidate_id=?", (candidate_id,))
                    raise ReplayAnchorUnavailable("external_anchor_compare_and_set_conflict_pending_not_accepted")
    else:
        with sqlite3.connect(str(database_path), timeout=5.0) as db:
            db.execute("UPDATE pending_anchored_replay SET status='CONFLICT' WHERE candidate_id=?", (candidate_id,))
        raise ReplayAnchorUnavailable("external_anchor_advanced_to_unrelated_head")

    # Never finalize from local metadata alone: verify the authoritative anchor again.
    final_sequence, final_head = _read_anchor(anchor_store, provider_id)
    if (final_sequence, final_head) != (candidate_sequence, candidate_head):
        raise ReplayAnchorUnavailable("external_anchor_changed_before_finalization")
    result = _finalize_pending(database_path, candidate_id=candidate_id,
        trusted_public_keys=trusted_public_keys)
    result["pending_candidate_id"] = candidate_id
    return result


def recover_pending_attestation(
    candidate_id: str,
    *,
    trusted_public_keys: Mapping[str, bytes],
    database_path: str | Path,
    anchor_store: ReplayAnchorStore,
) -> dict:
    """Recover one pending candidate without trusting local metadata as authority.

    If the authoritative anchor is still at the exact recorded prior head, a
    PREPARED candidate may attempt CAS again. If the anchor already equals the
    candidate, recovery verifies the signed evidence and finalizes it. Any other
    anchor state fails closed.
    """
    with sqlite3.connect(str(database_path), timeout=5.0) as db:
        _ensure_pending_schema(db)
        row = db.execute("""SELECT provider_id, run_id, nonce, receipt_sha256,
            expected_sequence, expected_head_sha256, candidate_sequence,
            candidate_head_sha256, dossier_json, envelope_json, status
            FROM pending_anchored_replay WHERE candidate_id=?""", (candidate_id,)).fetchone()
    if row is None:
        raise ReplayAnchorUnavailable("pending_candidate_missing")
    (provider_id, run_id, nonce, receipt_sha, prior_sequence, prior_head,
     candidate_sequence, candidate_head, dossier_json, envelope_json, status) = row
    if status not in ("PREPARED", "FINALIZED", "CONFLICT"):
        raise ReplayAnchorUnavailable("pending_candidate_status_invalid")
    if status in ("PREPARED", "FINALIZED"):
        # Validate the complete candidate before CAS. Local pending rows are not
        # an authority source: otherwise a modified candidate head could be
        # published while the anchor is still at the prior head.
        try:
            dossier = json.loads(dossier_json)
            envelope = json.loads(envelope_json)
            verified = verify_independent_runner_attestation(
                dossier, envelope, trusted_public_keys=trusted_public_keys
            )
        except (ValueError, TypeError, KeyError, AttributeError, IndexError) as exc:
            raise ReplayAnchorUnavailable("pending_evidence_reverification_failed") from exc
        if (dossier.get("runner", {}).get("provider_id"), dossier.get("run_id"),
            dossier.get("nonce"), verified.get("receipt_sha256")) != (
                provider_id, run_id, nonce, receipt_sha):
            raise ReplayAnchorUnavailable("pending_evidence_binding_mismatch")
        event, recomputed_head = _candidate(dossier, verified, prior_sequence, prior_head)
        if event["sequence"] != candidate_sequence or recomputed_head != candidate_head:
            raise ReplayAnchorUnavailable("pending_candidate_hash_mismatch")

    anchor_sequence, anchor_head = _read_anchor(anchor_store, provider_id)
    if (anchor_sequence, anchor_head) == (prior_sequence, prior_head):
        if status != "PREPARED":
            raise ReplayAnchorUnavailable("pending_candidate_conflict_requires_review")
        try:
            published = anchor_store.compare_and_set_anchor(
                provider_id, expected_sequence=prior_sequence,
                expected_head_sha256=prior_head, new_sequence=candidate_sequence,
                new_head_sha256=candidate_head,
            )
        except Exception as exc:
            anchor_sequence, anchor_head = _read_anchor(anchor_store, provider_id)
            if (anchor_sequence, anchor_head) != (candidate_sequence, candidate_head):
                raise ReplayAnchorUnavailable("pending_recovery_cas_outcome_unknown") from exc
        else:
            if published is not True:
                anchor_sequence, anchor_head = _read_anchor(anchor_store, provider_id)
                if (anchor_sequence, anchor_head) != (candidate_sequence, candidate_head):
                    raise ReplayAnchorUnavailable("pending_recovery_cas_conflict")
    elif (anchor_sequence, anchor_head) != (candidate_sequence, candidate_head):
        raise ReplayAnchorUnavailable("pending_candidate_not_confirmed_by_external_anchor")
    # Recovery must confirm the exact candidate head again immediately before
    # local finalization. The anchor may have changed after the first read or CAS.
    final_sequence, final_head = _read_anchor(anchor_store, provider_id)
    if (final_sequence, final_head) != (candidate_sequence, candidate_head):
        raise ReplayAnchorUnavailable("external_anchor_changed_before_finalization")
    result = _finalize_pending(database_path, candidate_id=candidate_id,
        trusted_public_keys=trusted_public_keys)
    result["pending_candidate_id"] = candidate_id
    result["recovered"] = True
    return result
