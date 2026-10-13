import sqlite3

import pytest

from shared import pending_anchored_attestation_replay as pending
from shared.anchored_attestation_replay import ReplayAnchorUnavailable
from test_attestation_replay_registry import _dossier, _envelope, _public_bytes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


GENESIS = "0" * 64


class Anchor:
    def __init__(self, provider_id="test-provider", cas_result=True):
        self.anchor = {"provider_id": provider_id, "sequence": 0, "head_sha256": GENESIS}
        self.cas_result = cas_result
        self.cas_calls = 0

    def get_anchor(self, provider_id):
        assert provider_id == self.anchor["provider_id"]
        return dict(self.anchor)

    def compare_and_set_anchor(self, provider_id, *, expected_sequence,
                               expected_head_sha256, new_sequence, new_head_sha256):
        self.cas_calls += 1
        if not self.cas_result:
            return False
        if (self.anchor["sequence"], self.anchor["head_sha256"]) != (
            expected_sequence, expected_head_sha256
        ):
            return False
        self.anchor = {"provider_id": provider_id, "sequence": new_sequence,
                       "head_sha256": new_head_sha256}
        return True


def _signed(run_id="pending-run", nonce="pending-nonce"):
    key = Ed25519PrivateKey.generate()
    dossier = _dossier(run_id, nonce)
    envelope = _envelope(dossier, key)
    trusted = {"pinned-runner-key": _public_bytes(key)}
    return dossier, envelope, trusted


def _counts(path):
    with sqlite3.connect(path) as db:
        accepted = db.execute("SELECT COUNT(*) FROM accepted_runner_attestations").fetchone()[0]
        pending_count = db.execute("SELECT COUNT(*) FROM pending_anchored_replay").fetchone()[0]
        finalized = db.execute("SELECT COUNT(*) FROM pending_anchored_replay WHERE status='FINALIZED'").fetchone()[0]
        return accepted, pending_count, finalized


def test_pending_protocol_success_only_after_anchor_and_local_finalize(tmp_path):
    path = tmp_path / "pending-success.sqlite3"
    dossier, envelope, trusted = _signed()
    anchor = Anchor()

    result = pending.verify_and_record_attestation_pending_anchored(
        dossier, envelope, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
    )

    assert result["valid"] is True
    assert result["qualification"] == "NOT_ESTABLISHED"
    assert result["journal"]["sequence"] == 1
    assert anchor.anchor["sequence"] == 1
    assert anchor.anchor["head_sha256"] == result["journal"]["head_sha256"]
    assert _counts(path) == (1, 1, 1)


def test_cas_conflict_keeps_candidate_pending_and_does_not_accept(tmp_path):
    path = tmp_path / "pending-conflict.sqlite3"
    dossier, envelope, trusted = _signed()
    anchor = Anchor(cas_result=False)

    with pytest.raises(ReplayAnchorUnavailable, match="compare_and_set_conflict_pending_not_accepted"):
        pending.verify_and_record_attestation_pending_anchored(
            dossier, envelope, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
        )

    assert anchor.anchor["sequence"] == 0
    assert _counts(path) == (0, 1, 0)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT sequence, head_sha256 FROM attestation_replay_journal_state WHERE provider_id=?",
                          ("test-provider",)).fetchone() is None
        assert db.execute("SELECT status FROM pending_anchored_replay").fetchone() == ("CONFLICT",)


def test_conflicted_candidate_cannot_be_republished_by_normal_entrypoint(tmp_path):
    path = tmp_path / "pending-conflict-republish.sqlite3"
    dossier, envelope, trusted = _signed("conflict-republish", "conflict-republish-nonce")
    anchor = Anchor(cas_result=False)

    with pytest.raises(ReplayAnchorUnavailable, match="compare_and_set_conflict_pending_not_accepted"):
        pending.verify_and_record_attestation_pending_anchored(
            dossier, envelope, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
        )
    assert anchor.cas_calls == 1

    # Even if the anchor later appears to return to genesis, an existing CONFLICT
    # candidate must not be silently republished by the regular write path.
    anchor.cas_result = True
    with pytest.raises(ReplayAnchorUnavailable, match="pending_candidate_conflict_requires_review"):
        pending.verify_and_record_attestation_pending_anchored(
            dossier, envelope, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
        )

    assert anchor.cas_calls == 1
    assert anchor.anchor["sequence"] == 0
    assert _counts(path) == (0, 1, 0)


def test_recovery_finalizes_exact_candidate_after_crash_post_cas(monkeypatch, tmp_path):
    path = tmp_path / "pending-crash.sqlite3"
    dossier, envelope, trusted = _signed("crash-after-cas", "crash-after-cas-nonce")
    anchor = Anchor()
    original_finalize = pending._finalize_pending

    def crash_before_finalize(*args, **kwargs):
        raise RuntimeError("simulated crash after anchor CAS")

    monkeypatch.setattr(pending, "_finalize_pending", crash_before_finalize)
    with pytest.raises(RuntimeError, match="simulated crash"):
        pending.verify_and_record_attestation_pending_anchored(
            dossier, envelope, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
        )

    assert anchor.anchor["sequence"] == 1
    assert _counts(path) == (0, 1, 0)
    with sqlite3.connect(path) as db:
        candidate_id = db.execute("SELECT candidate_id FROM pending_anchored_replay").fetchone()[0]

    monkeypatch.setattr(pending, "_finalize_pending", original_finalize)
    recovered = pending.recover_pending_attestation(
        candidate_id, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
    )
    assert recovered["recovered"] is True
    assert recovered["journal"]["head_sha256"] == anchor.anchor["head_sha256"]
    assert _counts(path) == (1, 1, 1)


def test_invalid_signature_never_creates_pending_or_accepted_state(tmp_path):
    path = tmp_path / "pending-invalid.sqlite3"
    dossier, envelope, trusted = _signed()
    envelope["signature"] = "00" * 64
    anchor = Anchor()

    with pytest.raises(pending.AttestationReplayRegistryError, match="attestation_invalid"):
        pending.verify_and_record_attestation_pending_anchored(
            dossier, envelope, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
        )
    assert not path.exists() or _counts(path) == (0, 0, 0)
    assert anchor.anchor["sequence"] == 0


def test_recovery_fails_closed_when_anchor_is_unrelated(tmp_path):
    path = tmp_path / "pending-unrelated.sqlite3"
    dossier, envelope, trusted = _signed("unrelated-anchor", "unrelated-anchor-nonce")
    anchor = Anchor(cas_result=False)
    with pytest.raises(ReplayAnchorUnavailable):
        pending.verify_and_record_attestation_pending_anchored(
            dossier, envelope, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
        )
    with sqlite3.connect(path) as db: candidate_id = db.execute("SELECT candidate_id FROM pending_anchored_replay").fetchone()[0]
    anchor.anchor = {"provider_id": "test-provider", "sequence": 1, "head_sha256": "1" * 64}
    with pytest.raises(ReplayAnchorUnavailable, match="pending_candidate_not_confirmed_by_external_anchor"):
        pending.recover_pending_attestation(
            candidate_id, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
        )
    assert _counts(path) == (0, 1, 0)


def test_pending_dossier_tamper_is_rejected_during_recovery(tmp_path, monkeypatch):
    original_finalize = pending._finalize_pending
    path = tmp_path / "pending-tamper.sqlite3"
    dossier, envelope, trusted = _signed("tamper-run", "tamper-nonce")
    anchor = Anchor()
    monkeypatch.setattr(pending, "_finalize_pending", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("crash")))
    with pytest.raises(RuntimeError, match="crash"):
        pending.verify_and_record_attestation_pending_anchored(
            dossier, envelope, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
        )
    with sqlite3.connect(path) as db:
        candidate_id = db.execute("SELECT candidate_id FROM pending_anchored_replay").fetchone()[0]
        db.execute("UPDATE pending_anchored_replay SET dossier_json='{}' WHERE candidate_id=?", (candidate_id,))
        monkeypatch.setattr(pending, "_finalize_pending", original_finalize)
    with pytest.raises(ReplayAnchorUnavailable, match="pending_evidence_reverification_failed"):
        pending.recover_pending_attestation(
            candidate_id, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
        )
    assert _counts(path) == (0, 1, 0)


def test_recovery_retries_prepared_candidate_when_anchor_stays_at_prior_head(tmp_path):
    path = tmp_path / "pending-before-cas.sqlite3"
    dossier, envelope, trusted = _signed("crash-before-cas", "crash-before-cas-nonce")
    anchor = Anchor()

    def crash_before_cas(*args, **kwargs):
        raise RuntimeError("simulated crash before CAS")

    anchor.compare_and_set_anchor = crash_before_cas
    with pytest.raises(ReplayAnchorUnavailable, match="external_anchor_publish_outcome_unknown"):
        pending.verify_and_record_attestation_pending_anchored(
            dossier, envelope, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
        )
    assert anchor.anchor["sequence"] == 0
    assert _counts(path) == (0, 1, 0)
    with sqlite3.connect(path) as db:
        candidate_id = db.execute("SELECT candidate_id FROM pending_anchored_replay").fetchone()[0]

    # Bind the normal CAS implementation to the same anchor object.
    def cas(provider_id, **kwargs):
        current = anchor.anchor
        if (current["sequence"], current["head_sha256"]) != (kwargs["expected_sequence"], kwargs["expected_head_sha256"]):
            return False
        anchor.anchor = {"provider_id": provider_id, "sequence": kwargs["new_sequence"], "head_sha256": kwargs["new_head_sha256"]}
        return True
    anchor.compare_and_set_anchor = cas
    recovered = pending.recover_pending_attestation(
        candidate_id, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
    )
    assert recovered["recovered"] is True
    assert anchor.anchor["sequence"] == 1
    assert _counts(path) == (1, 1, 1)


def test_ambiguous_cas_exception_recovers_only_if_anchor_advanced_to_candidate(tmp_path):
    path = tmp_path / "pending-ambiguous-cas.sqlite3"
    dossier, envelope, trusted = _signed("ambiguous-cas", "ambiguous-cas-nonce")
    anchor = Anchor()
    original_cas = anchor.compare_and_set_anchor

    def commit_then_timeout(*args, **kwargs):
        original_cas(*args, **kwargs)
        raise TimeoutError("response lost after commit")

    anchor.compare_and_set_anchor = commit_then_timeout
    result = pending.verify_and_record_attestation_pending_anchored(
        dossier, envelope, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
    )
    assert result["valid"] is True
    assert anchor.anchor["sequence"] == 1
    assert _counts(path) == (1, 1, 1)


def test_ambiguous_cas_exception_with_unchanged_anchor_fails_closed(tmp_path):
    path = tmp_path / "pending-ambiguous-no-commit.sqlite3"
    dossier, envelope, trusted = _signed("ambiguous-no-commit", "ambiguous-no-commit-nonce")
    anchor = Anchor()

    def timeout_without_commit(*args, **kwargs):
        raise TimeoutError("request outcome unknown")

    anchor.compare_and_set_anchor = timeout_without_commit
    with pytest.raises(ReplayAnchorUnavailable, match="external_anchor_publish_outcome_unknown"):
        pending.verify_and_record_attestation_pending_anchored(
            dossier, envelope, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
        )
    assert anchor.anchor["sequence"] == 0
    assert _counts(path) == (0, 1, 0)


def test_finalization_database_failure_can_be_recovered_idempotently(monkeypatch, tmp_path):
    path = tmp_path / "pending-finalize-failure.sqlite3"
    dossier, envelope, trusted = _signed("finalize-failure", "finalize-failure-nonce")
    anchor = Anchor()
    original_finalize = pending._finalize_pending

    def fail_finalize(*args, **kwargs):
        raise sqlite3.OperationalError("simulated local finalize failure")

    monkeypatch.setattr(pending, "_finalize_pending", fail_finalize)
    with pytest.raises(sqlite3.OperationalError, match="finalize failure"):
        pending.verify_and_record_attestation_pending_anchored(
            dossier, envelope, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
        )
    assert anchor.anchor["sequence"] == 1
    assert _counts(path) == (0, 1, 0)
    with sqlite3.connect(path) as db:
        candidate_id = db.execute("SELECT candidate_id FROM pending_anchored_replay").fetchone()[0]

    monkeypatch.setattr(pending, "_finalize_pending", original_finalize)
    recovered = pending.recover_pending_attestation(
        candidate_id, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
    )
    assert recovered["recovered"] is True
    assert _counts(path) == (1, 1, 1)


def test_concurrent_writers_from_same_anchor_accept_exactly_one_candidate(tmp_path):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    path = tmp_path / "pending-concurrent-writers.sqlite3"
    barrier = threading.Barrier(2)
    lock = threading.Lock()
    anchor = Anchor()
    original_cas = anchor.compare_and_set_anchor

    def synchronized_cas(provider_id, **kwargs):
        # Both writers must stage their candidate before either can publish.
        barrier.wait(timeout=5)
        with lock:
            return original_cas(provider_id, **kwargs)

    anchor.compare_and_set_anchor = synchronized_cas
    first = _signed("concurrent-run-a", "concurrent-nonce-a")
    second = _signed("concurrent-run-b", "concurrent-nonce-b")

    def submit(signed):
        dossier, envelope, trusted = signed
        try:
            result = pending.verify_and_record_attestation_pending_anchored(
                dossier, envelope, trusted_public_keys=trusted,
                database_path=path, anchor_store=anchor,
            )
            return ("accepted", result)
        except Exception as exc:
            return ("rejected", exc)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(submit, (first, second)))

    accepted = [outcome for outcome in outcomes if outcome[0] == "accepted"]
    rejected = [outcome for outcome in outcomes if outcome[0] == "rejected"]
    assert len(accepted) == 1, outcomes
    assert len(rejected) == 1, outcomes
    assert isinstance(rejected[0][1], ReplayAnchorUnavailable)
    assert anchor.anchor["sequence"] == 1
    assert accepted[0][1]["journal"]["head_sha256"] == anchor.anchor["head_sha256"]

    with sqlite3.connect(path) as db:
        accepted_rows = db.execute(
            "SELECT run_id, nonce FROM accepted_runner_attestations WHERE provider_id=?",
            ("test-provider",),
        ).fetchall()
        pending_rows = db.execute(
            "SELECT run_id, status FROM pending_anchored_replay ORDER BY run_id"
        ).fetchall()
        journal_state = db.execute(
            "SELECT sequence, head_sha256 FROM attestation_replay_journal_state WHERE provider_id=?",
            ("test-provider",),
        ).fetchone()

    assert len(accepted_rows) == 1
    assert journal_state == (1, anchor.anchor["head_sha256"])
    assert len(pending_rows) == 2
    assert sorted(status for _, status in pending_rows) == ["CONFLICT", "FINALIZED"]


def test_recovery_after_database_reopen_is_idempotent(tmp_path, monkeypatch):
    path = tmp_path / "pending-reopen.sqlite3"
    dossier, envelope, trusted = _signed("restart-run", "restart-nonce")
    anchor = Anchor()
    original_finalize = pending._finalize_pending

    def crash_after_anchor(*args, **kwargs):
        raise RuntimeError("simulated process termination")

    monkeypatch.setattr(pending, "_finalize_pending", crash_after_anchor)
    with pytest.raises(RuntimeError, match="process termination"):
        pending.verify_and_record_attestation_pending_anchored(
            dossier, envelope, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
        )
    with sqlite3.connect(path) as db:
        candidate_id = db.execute(
            "SELECT candidate_id FROM pending_anchored_replay WHERE status='PREPARED'"
        ).fetchone()[0]

    # Reopening through fresh SQLite connections and the recovery API models a restart.
    monkeypatch.setattr(pending, "_finalize_pending", original_finalize)
    first = pending.recover_pending_attestation(
        candidate_id, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
    )
    second = pending.recover_pending_attestation(
        candidate_id, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
    )
    assert first["recovered"] is True
    assert second["recovered"] is True
    assert _counts(path) == (1, 1, 1)
    assert anchor.anchor["sequence"] == 1


def test_conflicted_candidate_cannot_be_recovered_from_later_matching_head(tmp_path):
    path = tmp_path / "pending-conflict-recovery.sqlite3"
    dossier, envelope, trusted = _signed("conflict-recovery", "conflict-recovery-nonce")
    anchor = Anchor(cas_result=False)
    with pytest.raises(ReplayAnchorUnavailable, match="compare_and_set_conflict_pending_not_accepted"):
        pending.verify_and_record_attestation_pending_anchored(
            dossier, envelope, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
        )
    with sqlite3.connect(path) as db:
        candidate_id, candidate_sequence, candidate_head = db.execute(
            "SELECT candidate_id, candidate_sequence, candidate_head_sha256 "
            "FROM pending_anchored_replay"
        ).fetchone()
    # Simulate an anchor rollback or inconsistent external implementation. A CONFLICT
    # record is never promoted just because its old candidate hash reappears.
    anchor.anchor = {"provider_id": "test-provider", "sequence": candidate_sequence,
                     "head_sha256": candidate_head}
    with pytest.raises(ReplayAnchorUnavailable, match="pending_candidate_conflict_requires_review"):
        pending.recover_pending_attestation(
            candidate_id, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
        )
    assert _counts(path) == (0, 1, 0)


def test_recovery_detects_anchor_rollback_when_local_finalized_state_survives(tmp_path):
    path = tmp_path / "pending-anchor-rollback.sqlite3"
    dossier, envelope, trusted = _signed("rollback-detection", "rollback-detection-nonce")
    anchor = Anchor()
    result = pending.verify_and_record_attestation_pending_anchored(
        dossier, envelope, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
    )
    assert result["journal"]["sequence"] == 1
    assert _counts(path) == (1, 1, 1)

    # Model a broken anchor service that regresses after a confirmed commit.
    # The surviving local finalized state must prevent silent re-acceptance.
    anchor.anchor = {"provider_id": "test-provider", "sequence": 0, "head_sha256": GENESIS}
    with sqlite3.connect(path) as db:
        candidate_id = db.execute(
            "SELECT candidate_id FROM pending_anchored_replay"
        ).fetchone()[0]

    with pytest.raises(ReplayAnchorUnavailable, match="pending_candidate_conflict_requires_review"):
        pending.recover_pending_attestation(
            candidate_id, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
        )
    assert _counts(path) == (1, 1, 1)
    assert anchor.anchor["sequence"] == 0


def test_legacy_accepted_state_without_journal_head_fails_before_anchor_cas(tmp_path):
    path = tmp_path / "legacy-state.sqlite3"
    dossier, envelope, trusted = _signed("new-run-after-legacy", "new-nonce-after-legacy")
    anchor = Anchor()
    # Create the legacy accepted table layout and a prior accepted row, but no
    # journal state. This must require an explicit migration before anchoring.
    from shared.attestation_replay_registry import _ensure_schema
    with sqlite3.connect(path) as db:
        _ensure_schema(db)
        db.execute(
            "INSERT INTO accepted_runner_attestations "
            "(provider_id, key_id, run_id, nonce, receipt_sha256) VALUES (?, ?, ?, ?, ?)",
            ("test-provider", "legacy-key", "legacy-run", "legacy-nonce", "a" * 64),
        )

    with pytest.raises(Exception, match="replay_registry_legacy_state_requires_migration"):
        pending.verify_and_record_attestation_pending_anchored(
            dossier, envelope, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
        )

    assert anchor.cas_calls == 0
    assert anchor.anchor["sequence"] == 0
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM accepted_runner_attestations").fetchone()[0] == 1
        assert db.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='pending_anchored_replay'"
        ).fetchone()[0] == 0


def test_tampered_candidate_head_is_rejected_during_recovery(tmp_path, monkeypatch):
    path = tmp_path / "pending-candidate-head-tamper.sqlite3"
    dossier, envelope, trusted = _signed("candidate-head-tamper", "candidate-head-tamper-nonce")
    anchor = Anchor()
    original_finalize = pending._finalize_pending

    def crash_after_anchor(*args, **kwargs):
        raise RuntimeError("simulated crash after anchor")

    monkeypatch.setattr(pending, "_finalize_pending", crash_after_anchor)
    with pytest.raises(RuntimeError, match="after anchor"):
        pending.verify_and_record_attestation_pending_anchored(
            dossier, envelope, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
        )

    with sqlite3.connect(path) as db:
        candidate_id = db.execute(
            "SELECT candidate_id FROM pending_anchored_replay"
        ).fetchone()[0]
        db.execute(
            "UPDATE pending_anchored_replay SET candidate_head_sha256=? WHERE candidate_id=?",
            ("f" * 64, candidate_id),
        )

    monkeypatch.setattr(pending, "_finalize_pending", original_finalize)
    with pytest.raises(ReplayAnchorUnavailable, match="pending_candidate_hash_mismatch"):
        pending.recover_pending_attestation(
            candidate_id, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
        )
    # The corrupted local head no longer matches the authoritative anchor, so recovery
    # stops before evidence verification/finalization and never accepts the candidate.
    assert _counts(path) == (0, 1, 0)
    assert anchor.anchor["sequence"] == 1


def test_malformed_external_anchor_fails_before_pending_state_or_cas(tmp_path):
    path = tmp_path / "pending-malformed-anchor.sqlite3"
    dossier, envelope, trusted = _signed("malformed-anchor", "malformed-anchor-nonce")
    anchor = Anchor()
    anchor.anchor = {"provider_id": "test-provider", "sequence": True, "head_sha256": GENESIS}

    with pytest.raises(ReplayAnchorUnavailable, match="external_anchor_sequence_invalid"):
        pending.verify_and_record_attestation_pending_anchored(
            dossier, envelope, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
        )

    assert anchor.cas_calls == 0
    assert not path.exists() or not path.stat().st_size or _counts(path) == (0, 0, 0)


@pytest.mark.parametrize("duplicate_field", ["run_id", "nonce"])
def test_accepted_run_id_or_nonce_cannot_be_replayed_through_pending_protocol(
    tmp_path, duplicate_field
):
    path = tmp_path / f"pending-replay-{duplicate_field}.sqlite3"
    first_dossier, first_envelope, first_trusted = _signed(
        f"replay-{duplicate_field}-run", f"replay-{duplicate_field}-nonce"
    )
    anchor = Anchor()
    pending.verify_and_record_attestation_pending_anchored(
        first_dossier, first_envelope, trusted_public_keys=first_trusted,
        database_path=path, anchor_store=anchor,
    )

    if duplicate_field == "run_id":
        second_dossier, second_envelope, second_trusted = _signed(
            first_dossier["run_id"], "fresh-nonce-for-duplicate-run"
        )
    else:
        second_dossier, second_envelope, second_trusted = _signed(
            "fresh-run-for-duplicate-nonce", first_dossier["nonce"]
        )

    with pytest.raises(pending.AttestationReplayRegistryError, match="attestation_replay_detected:run_id_or_nonce_already_seen"):
        pending.verify_and_record_attestation_pending_anchored(
            second_dossier, second_envelope, trusted_public_keys=second_trusted,
            database_path=path, anchor_store=anchor,
        )

    assert anchor.cas_calls == 1
    assert anchor.anchor["sequence"] == 1
    assert _counts(path) == (1, 1, 1)


def test_local_finalize_sqlite_failure_is_recoverable_after_anchor_advance(tmp_path, monkeypatch):
    path = tmp_path / "pending-finalize-sqlite-failure.sqlite3"
    dossier, envelope, trusted = _signed("sqlite-failure-run", "sqlite-failure-nonce")
    anchor = Anchor()
    original_finalize = pending.verify_and_record_attestation

    def fail_once(*args, **kwargs):
        raise sqlite3.OperationalError("simulated local finalization write failure")

    monkeypatch.setattr(pending, "verify_and_record_attestation", fail_once)
    with pytest.raises(sqlite3.OperationalError, match="simulated local finalization write failure"):
        pending.verify_and_record_attestation_pending_anchored(
            dossier, envelope, trusted_public_keys=trusted,
            database_path=path, anchor_store=anchor,
        )

    with sqlite3.connect(path) as db:
        candidate_id = db.execute(
            "SELECT candidate_id FROM pending_anchored_replay WHERE status='PREPARED'"
        ).fetchone()[0]
    assert anchor.anchor["sequence"] == 1
    assert _counts(path) == (0, 1, 0)

    monkeypatch.setattr(pending, "verify_and_record_attestation", original_finalize)
    recovered = pending.recover_pending_attestation(
        candidate_id, trusted_public_keys=trusted,
        database_path=path, anchor_store=anchor,
    )
    assert recovered["valid"] is True
    assert recovered["recovered"] is True
    assert recovered["journal"]["sequence"] == 1
    assert _counts(path) == (1, 1, 1)
    assert anchor.anchor["sequence"] == 1


def test_recovery_fails_closed_on_corrupt_local_journal_even_when_terminal_state_matches_anchor(tmp_path):
    from shared.replay_registry_recovery import ReplayRecoveryError, build_replay_recovery_plan

    path = tmp_path / "pending-corrupt-journal.sqlite3"
    dossier, envelope, trusted = _signed("corrupt-journal-run", "corrupt-journal-nonce")
    anchor = Anchor()
    result = pending.verify_and_record_attestation_pending_anchored(
        dossier, envelope, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
    )
    assert result["valid"] is True

    # Keep the terminal state row equal to the external anchor while corrupting
    # the underlying event. Checking only the terminal digest would miss this.
    with sqlite3.connect(path) as db:
        db.execute(
            "UPDATE attestation_replay_journal SET head_sha256=? WHERE provider_id=? AND sequence=1",
            ("f" * 64, "test-provider"),
        )

    with pytest.raises(ReplayRecoveryError, match="recovery_journal_chain_corrupt"):
        build_replay_recovery_plan(
            path,
            provider_id="test-provider",
            anchor_sequence=anchor.anchor["sequence"],
            anchor_head_sha256=anchor.anchor["head_sha256"],
            trusted_public_keys=trusted,
        )
    assert anchor.anchor["sequence"] == 1
    assert _counts(path) == (1, 1, 1)


def test_recovery_fails_closed_when_journal_row_is_missing(tmp_path):
    from shared.replay_registry_recovery import ReplayRecoveryError, build_replay_recovery_plan

    path = tmp_path / "pending-missing-journal-row.sqlite3"
    dossier, envelope, trusted = _signed("missing-journal-row-run", "missing-journal-row-nonce")
    anchor = Anchor()
    pending.verify_and_record_attestation_pending_anchored(
        dossier, envelope, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
    )
    with sqlite3.connect(path) as db:
        db.execute("DELETE FROM attestation_replay_journal WHERE provider_id=? AND sequence=1", ("test-provider",))

    with pytest.raises(ReplayRecoveryError, match="recovery_journal_or_evidence_count_mismatch"):
        build_replay_recovery_plan(
            path, provider_id="test-provider", anchor_sequence=anchor.anchor["sequence"],
            anchor_head_sha256=anchor.anchor["head_sha256"], trusted_public_keys=trusted,
        )
    assert anchor.anchor["sequence"] == 1


def test_recovery_fails_closed_when_evidence_row_is_missing(tmp_path):
    from shared.replay_registry_recovery import ReplayRecoveryError, build_replay_recovery_plan

    path = tmp_path / "pending-missing-evidence-row.sqlite3"
    dossier, envelope, trusted = _signed("missing-evidence-row-run", "missing-evidence-row-nonce")
    anchor = Anchor()
    pending.verify_and_record_attestation_pending_anchored(
        dossier, envelope, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
    )
    with sqlite3.connect(path) as db:
        db.execute("DELETE FROM attestation_replay_evidence WHERE provider_id=? AND sequence=1", ("test-provider",))

    with pytest.raises(ReplayRecoveryError, match="recovery_journal_or_evidence_count_mismatch"):
        build_replay_recovery_plan(
            path, provider_id="test-provider", anchor_sequence=anchor.anchor["sequence"],
            anchor_head_sha256=anchor.anchor["head_sha256"], trusted_public_keys=trusted,
        )
    assert anchor.anchor["sequence"] == 1


def test_recovery_rejects_tampered_candidate_before_anchor_cas(tmp_path):
    path = tmp_path / "pending-tampered-before-cas.sqlite3"
    dossier, envelope, trusted = _signed("tamper-before-cas", "tamper-before-cas-nonce")
    anchor = Anchor()
    def unknown_cas(*args, **kwargs):
        raise RuntimeError("simulated lost CAS response")
    anchor.compare_and_set_anchor = unknown_cas
    with pytest.raises(ReplayAnchorUnavailable, match="external_anchor_publish_outcome_unknown"):
        pending.verify_and_record_attestation_pending_anchored(
            dossier, envelope, trusted_public_keys=trusted, database_path=path,
            anchor_store=anchor,
        )
    with sqlite3.connect(path) as db:
        candidate_id = db.execute("SELECT candidate_id FROM pending_anchored_replay").fetchone()[0]
        db.execute(
            "UPDATE pending_anchored_replay SET candidate_head_sha256=? WHERE candidate_id=?",
            ("e" * 64, candidate_id),
        )

    with pytest.raises(ReplayAnchorUnavailable, match="pending_candidate_hash_mismatch"):
        pending.recover_pending_attestation(
            candidate_id, trusted_public_keys=trusted, database_path=path, anchor_store=anchor,
        )

    assert anchor.cas_calls == 0
    assert anchor.anchor["sequence"] == 0
    assert _counts(path) == (0, 1, 0)


def test_independent_database_snapshots_compete_for_same_anchor_sequence(tmp_path):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    # Two independent restored copies both start from the same provider genesis.
    first_path = tmp_path / "restored-copy-a.sqlite3"
    second_path = tmp_path / "restored-copy-b.sqlite3"
    first_signed = _signed("snapshot-copy-a", "snapshot-nonce-a")
    second_signed = _signed("snapshot-copy-b", "snapshot-nonce-b")
    anchor = Anchor()
    barrier = threading.Barrier(2)
    lock = threading.Lock()
    original_cas = anchor.compare_and_set_anchor

    def synchronized_cas(provider_id, **kwargs):
        # Force both independent copies to reach CAS after observing genesis.
        barrier.wait(timeout=5)
        with lock:
            return original_cas(provider_id, **kwargs)

    anchor.compare_and_set_anchor = synchronized_cas

    def submit(path, signed):
        dossier, envelope, trusted = signed
        try:
            result = pending.verify_and_record_attestation_pending_anchored(
                dossier, envelope, trusted_public_keys=trusted,
                database_path=path, anchor_store=anchor,
            )
            return ("accepted", result, path)
        except Exception as exc:
            return ("rejected", exc, path)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(
            lambda args: submit(*args),
            ((first_path, first_signed), (second_path, second_signed)),
        ))

    accepted = [item for item in outcomes if item[0] == "accepted"]
    rejected = [item for item in outcomes if item[0] == "rejected"]
    assert len(accepted) == 1, outcomes
    assert len(rejected) == 1, outcomes
    assert isinstance(rejected[0][1], ReplayAnchorUnavailable)
    assert anchor.anchor["sequence"] == 1
    assert accepted[0][1]["journal"]["head_sha256"] == anchor.anchor["head_sha256"]

    with sqlite3.connect(accepted[0][2]) as db:
        assert db.execute("SELECT COUNT(*) FROM accepted_runner_attestations").fetchone()[0] == 1
        assert db.execute(
            "SELECT sequence, head_sha256 FROM attestation_replay_journal_state WHERE provider_id=?",
            ("test-provider",),
        ).fetchone() == (1, anchor.anchor["head_sha256"])
    with sqlite3.connect(rejected[0][2]) as db:
        assert db.execute("SELECT COUNT(*) FROM accepted_runner_attestations").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM attestation_replay_journal").fetchone()[0] == 0
        assert db.execute("SELECT status FROM pending_anchored_replay").fetchone() == ("CONFLICT",)


def test_concurrent_recovery_of_same_prepared_candidate_is_idempotent(tmp_path):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    path = tmp_path / "pending-concurrent-recovery.sqlite3"
    dossier, envelope, trusted = _signed("concurrent-recovery", "concurrent-recovery-nonce")
    anchor = Anchor()

    def lose_response(*args, **kwargs):
        raise TimeoutError("simulated lost CAS response")

    anchor.compare_and_set_anchor = lose_response
    with pytest.raises(ReplayAnchorUnavailable, match="external_anchor_publish_outcome_unknown"):
        pending.verify_and_record_attestation_pending_anchored(
            dossier, envelope, trusted_public_keys=trusted,
            database_path=path, anchor_store=anchor,
        )
    with sqlite3.connect(path) as db:
        candidate_id = db.execute(
            "SELECT candidate_id FROM pending_anchored_replay WHERE status='PREPARED'"
        ).fetchone()[0]

    barrier = threading.Barrier(2)
    lock = threading.Lock()
    original_cas = Anchor.compare_and_set_anchor

    def synchronized_cas(provider_id, **kwargs):
        barrier.wait(timeout=5)
        with lock:
            return original_cas(anchor, provider_id, **kwargs)

    anchor.compare_and_set_anchor = synchronized_cas

    def recover():
        return pending.recover_pending_attestation(
            candidate_id, trusted_public_keys=trusted,
            database_path=path, anchor_store=anchor,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: recover(), range(2)))

    assert all(result["recovered"] is True for result in outcomes)
    assert anchor.anchor["sequence"] == 1
    assert _counts(path) == (1, 1, 1)
    with sqlite3.connect(path) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM accepted_runner_attestations"
        ).fetchone()[0] == 1
        assert db.execute(
            "SELECT COUNT(*) FROM pending_anchored_replay WHERE status='FINALIZED'"
        ).fetchone()[0] == 1


def test_independent_anchor_forks_can_each_accept_a_different_sequence_one(tmp_path):
    # This is an explicit limit test: per-store CAS cannot coordinate two stores.
    first_path = tmp_path / "fork-copy-a.sqlite3"
    second_path = tmp_path / "fork-copy-b.sqlite3"
    first_signed = _signed("fork-copy-a", "fork-nonce-a")
    second_signed = _signed("fork-copy-b", "fork-nonce-b")
    first_anchor = Anchor()
    second_anchor = Anchor()

    outcomes = []
    for path, signed, anchor in (
        (first_path, first_signed, first_anchor),
        (second_path, second_signed, second_anchor),
    ):
        dossier, envelope, trusted = signed
        outcomes.append(pending.verify_and_record_attestation_pending_anchored(
            dossier, envelope, trusted_public_keys=trusted,
            database_path=path, anchor_store=anchor,
        ))

    assert all(result["valid"] is True for result in outcomes)
    assert first_anchor.anchor["sequence"] == second_anchor.anchor["sequence"] == 1
    assert first_anchor.anchor["head_sha256"] != second_anchor.anchor["head_sha256"]
    assert _counts(first_path) == (1, 1, 1)
    assert _counts(second_path) == (1, 1, 1)


def test_recovery_rejects_anchor_that_has_advanced_past_pending_candidate(tmp_path):
    path = tmp_path / "pending-anchor-ahead.sqlite3"
    dossier, envelope, trusted = _signed("anchor-ahead", "anchor-ahead-nonce")
    anchor = Anchor(cas_result=False)

    with pytest.raises(ReplayAnchorUnavailable, match="compare_and_set_conflict_pending_not_accepted"):
        pending.verify_and_record_attestation_pending_anchored(
            dossier, envelope, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
        )
    with sqlite3.connect(path) as db:
        candidate_id = db.execute(
            "SELECT candidate_id FROM pending_anchored_replay"
        ).fetchone()[0]

    # The candidate was prepared for sequence 1. A later sequence is not proof
    # that this candidate is in the authoritative chain, even if its local hash
    # and signed evidence still verify.
    anchor.anchor = {
        "provider_id": "test-provider",
        "sequence": 2,
        "head_sha256": "2" * 64,
    }
    with pytest.raises(
        ReplayAnchorUnavailable,
        match="pending_candidate_not_confirmed_by_external_anchor",
    ):
        pending.recover_pending_attestation(
            candidate_id,
            trusted_public_keys=trusted,
            database_path=path,
            anchor_store=anchor,
        )

    assert _counts(path) == (0, 1, 0)
    with sqlite3.connect(path) as db:
        assert db.execute(
            "SELECT status FROM pending_anchored_replay WHERE candidate_id=?",
            (candidate_id,),
        ).fetchone() == ("CONFLICT",)


def test_recovery_anchor_read_failure_does_not_accept_pending_candidate(tmp_path):
    path = tmp_path / "pending-anchor-read-failure.sqlite3"
    dossier, envelope, trusted = _signed("anchor-read-failure", "anchor-read-failure-nonce")
    anchor = Anchor()

    def lose_cas_response(*args, **kwargs):
        raise TimeoutError("simulated lost response")

    anchor.compare_and_set_anchor = lose_cas_response
    with pytest.raises(ReplayAnchorUnavailable, match="external_anchor_publish_outcome_unknown"):
        pending.verify_and_record_attestation_pending_anchored(
            dossier, envelope, trusted_public_keys=trusted,
            database_path=path, anchor_store=anchor,
        )
    with sqlite3.connect(path) as db:
        candidate_id = db.execute(
            "SELECT candidate_id FROM pending_anchored_replay WHERE status='PREPARED'"
        ).fetchone()[0]

    def unavailable_read(provider_id):
        raise TimeoutError("anchor read unavailable")

    anchor.get_anchor = unavailable_read
    with pytest.raises(ReplayAnchorUnavailable, match="external_anchor_unavailable_fail_closed"):
        pending.recover_pending_attestation(
            candidate_id, trusted_public_keys=trusted,
            database_path=path, anchor_store=anchor,
        )

    assert _counts(path) == (0, 1, 0)
    with sqlite3.connect(path) as db:
        assert db.execute(
            "SELECT status FROM pending_anchored_replay WHERE candidate_id=?",
            (candidate_id,),
        ).fetchone() == ("PREPARED",)


def test_recovery_rechecks_anchor_immediately_before_finalization(monkeypatch, tmp_path):
    path = tmp_path / "pending-recovery-anchor-advance.sqlite3"
    dossier, envelope, trusted = _signed(
        "recovery-anchor-advance", "recovery-anchor-advance-nonce"
    )
    anchor = Anchor()
    original_finalize = pending._finalize_pending

    def crash_after_anchor(*args, **kwargs):
        raise RuntimeError("simulated crash after anchor CAS")

    monkeypatch.setattr(pending, "_finalize_pending", crash_after_anchor)
    with pytest.raises(RuntimeError, match="simulated crash"):
        pending.verify_and_record_attestation_pending_anchored(
            dossier, envelope, trusted_public_keys=trusted,
            database_path=path, anchor_store=anchor,
        )
    with sqlite3.connect(path) as db:
        candidate_id = db.execute(
            "SELECT candidate_id FROM pending_anchored_replay"
        ).fetchone()[0]
    assert anchor.anchor["sequence"] == 1
    assert _counts(path) == (0, 1, 0)

    monkeypatch.setattr(pending, "_finalize_pending", original_finalize)
    original_read_anchor = pending._read_anchor
    reads = 0

    def anchor_advances_between_reads(store, provider_id):
        nonlocal reads
        reads += 1
        if reads == 1:
            return original_read_anchor(store, provider_id)
        return 2, "2" * 64

    monkeypatch.setattr(pending, "_read_anchor", anchor_advances_between_reads)
    with pytest.raises(
        ReplayAnchorUnavailable,
        match="external_anchor_changed_before_finalization",
    ):
        pending.recover_pending_attestation(
            candidate_id, trusted_public_keys=trusted,
            database_path=path, anchor_store=anchor,
        )

    assert reads == 2
    assert _counts(path) == (0, 1, 0)


def test_recovery_rejects_unknown_pending_status_even_when_anchor_matches(monkeypatch, tmp_path):
    path = tmp_path / "pending-invalid-status.sqlite3"
    dossier, envelope, trusted = _signed(
        "invalid-pending-status", "invalid-pending-status-nonce"
    )
    anchor = Anchor()
    original_finalize = pending._finalize_pending

    def crash_after_anchor(*args, **kwargs):
        raise RuntimeError("simulated crash after anchor CAS")

    monkeypatch.setattr(pending, "_finalize_pending", crash_after_anchor)
    with pytest.raises(RuntimeError, match="simulated crash"):
        pending.verify_and_record_attestation_pending_anchored(
            dossier, envelope, trusted_public_keys=trusted,
            database_path=path, anchor_store=anchor,
        )
    with sqlite3.connect(path) as db:
        candidate_id = db.execute(
            "SELECT candidate_id FROM pending_anchored_replay"
        ).fetchone()[0]
        db.execute("PRAGMA ignore_check_constraints=ON")
        db.execute(
            "UPDATE pending_anchored_replay SET status='UNKNOWN' WHERE candidate_id=?",
            (candidate_id,),
        )

    monkeypatch.setattr(pending, "_finalize_pending", original_finalize)
    with pytest.raises(ReplayAnchorUnavailable, match="pending_candidate_status_invalid"):
        pending.recover_pending_attestation(
            candidate_id, trusted_public_keys=trusted,
            database_path=path, anchor_store=anchor,
        )

    assert anchor.anchor["sequence"] == 1
    assert _counts(path) == (0, 1, 0)
