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

    with pytest.raises(Exception, match="attestation_invalid"):
        pending.verify_and_record_attestation_pending_anchored(
            dossier, envelope, trusted_public_keys=trusted, database_path=path, anchor_store=anchor
        )
    assert not path.exists() or _counts(path) == (0, 0, 0)
    assert anchor.anchor["sequence"] == 0
