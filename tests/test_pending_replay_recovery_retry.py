import sqlite3

import pytest

from shared import pending_anchored_attestation_replay as pending
from test_pending_anchored_attestation_replay import Anchor, _counts, _signed


def test_recovery_retries_after_atomic_finalization_trigger_is_removed(tmp_path):
    path = tmp_path / "pending-finalize-trigger-retry.sqlite3"
    dossier, envelope, trusted = _signed(
        "finalize-trigger-retry", "finalize-trigger-retry-nonce"
    )
    anchor = Anchor()
    original_cas = anchor.compare_and_set_anchor

    def cas_then_install_failure_trigger(*args, **kwargs):
        result = original_cas(*args, **kwargs)
        if result:
            with sqlite3.connect(path) as db:
                db.execute(
                    """CREATE TRIGGER fail_pending_finalized_update
                       BEFORE UPDATE OF status ON pending_anchored_replay
                       WHEN NEW.status='FINALIZED'
                       BEGIN
                           SELECT RAISE(ABORT, 'simulated_finalize_write_failure');
                       END"""
                )
        return result

    anchor.compare_and_set_anchor = cas_then_install_failure_trigger

    with pytest.raises(
        pending.AttestationReplayRegistryError,
        match="replay_registry_integrity_constraint_failed",
    ):
        pending.verify_and_record_attestation_pending_anchored(
            dossier,
            envelope,
            trusted_public_keys=trusted,
            database_path=path,
            anchor_store=anchor,
        )

    assert anchor.anchor["sequence"] == 1
    assert _counts(path) == (0, 1, 0)

    # The external anchor committed, but the local acceptance transaction rolled
    # back. Once the injected storage fault is removed, recovery must finalize
    # this exact PREPARED candidate without publishing a second anchor entry.
    with sqlite3.connect(path) as db:
        candidate_id = db.execute(
            "SELECT candidate_id FROM pending_anchored_replay WHERE status='PREPARED'"
        ).fetchone()[0]
        db.execute("DROP TRIGGER fail_pending_finalized_update")

    first = pending.recover_pending_attestation(
        candidate_id,
        trusted_public_keys=trusted,
        database_path=path,
        anchor_store=anchor,
    )
    assert first["recovered"] is True
    assert first["journal"]["sequence"] == 1
    assert _counts(path) == (1, 1, 1)

    second = pending.recover_pending_attestation(
        candidate_id,
        trusted_public_keys=trusted,
        database_path=path,
        anchor_store=anchor,
    )
    assert second["recovered"] is True
    assert second["journal"]["sequence"] == 1
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
