import sqlite3

import pytest

from shared import pending_anchored_attestation_replay as pending
from shared.anchored_attestation_replay import ReplayAnchorUnavailable
from test_pending_anchored_attestation_replay import Anchor, _counts, _signed


def test_conflicted_candidate_stays_quarantined_even_if_anchor_later_matches(tmp_path):
    path = tmp_path / "conflict-anchor-match.sqlite3"
    dossier, envelope, trusted = _signed(
        "conflict-later-matches", "conflict-later-matches-nonce"
    )
    anchor = Anchor(cas_result=False)

    with pytest.raises(ReplayAnchorUnavailable, match="compare_and_set_conflict_pending_not_accepted"):
        pending.verify_and_record_attestation_pending_anchored(
            dossier,
            envelope,
            trusted_public_keys=trusted,
            database_path=path,
            anchor_store=anchor,
        )

    with sqlite3.connect(path) as db:
        row = db.execute(
            "SELECT candidate_id, candidate_sequence, candidate_head_sha256, status "
            "FROM pending_anchored_replay"
        ).fetchone()
    candidate_id, sequence, head, status = row
    assert status == "CONFLICT"
    assert _counts(path) == (0, 1, 0)

    # Even a later exact-looking anchor match cannot erase the conflict history.
    anchor.anchor = {
        "provider_id": "test-provider",
        "sequence": sequence,
        "head_sha256": head,
    }
    with pytest.raises(ReplayAnchorUnavailable, match="pending_candidate_conflict_requires_review"):
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
        assert db.execute("SELECT COUNT(*) FROM attestation_replay_journal").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM attestation_replay_evidence").fetchone()[0] == 0
