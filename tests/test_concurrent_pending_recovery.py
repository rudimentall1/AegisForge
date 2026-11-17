from concurrent.futures import ThreadPoolExecutor
import sqlite3

import pytest

from shared import pending_anchored_attestation_replay as pending
from test_pending_anchored_attestation_replay import Anchor, _counts, _signed


def test_two_recovery_workers_finalize_same_anchored_candidate_once(monkeypatch, tmp_path):
    path = tmp_path / "concurrent-recovery.sqlite3"
    dossier, envelope, trusted = _signed(
        "concurrent-recovery", "concurrent-recovery-nonce"
    )
    anchor = Anchor()

    def simulate_crash_after_anchor(*args, **kwargs):
        raise RuntimeError("simulated crash after anchor CAS")

    monkeypatch.setattr(pending, "_finalize_pending", simulate_crash_after_anchor)
    with pytest.raises(RuntimeError, match="simulated crash"):
        pending.verify_and_record_attestation_pending_anchored(
            dossier,
            envelope,
            trusted_public_keys=trusted,
            database_path=path,
            anchor_store=anchor,
        )

    with sqlite3.connect(path) as db:
        candidate_id = db.execute(
            "SELECT candidate_id FROM pending_anchored_replay WHERE status='PREPARED'"
        ).fetchone()[0]
    assert anchor.anchor["sequence"] == 1
    assert _counts(path) == (0, 1, 0)

    monkeypatch.undo()

    def recover():
        return pending.recover_pending_attestation(
            candidate_id,
            trusted_public_keys=trusted,
            database_path=path,
            anchor_store=anchor,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: recover(), range(2)))

    assert all(result["valid"] is True for result in results)
    assert all(result["recovered"] is True for result in results)
    assert all(result["journal"]["sequence"] == 1 for result in results)
    assert _counts(path) == (1, 1, 1)

    with sqlite3.connect(path) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM attestation_replay_journal WHERE provider_id=?",
            ("test-provider",),
        ).fetchone()[0] == 1
        assert db.execute(
            "SELECT COUNT(*) FROM attestation_replay_evidence WHERE provider_id=?",
            ("test-provider",),
        ).fetchone()[0] == 1
        assert db.execute(
            "SELECT status FROM pending_anchored_replay WHERE candidate_id=?",
            (candidate_id,),
        ).fetchone() == ("FINALIZED",)
