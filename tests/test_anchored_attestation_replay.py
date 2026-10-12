import sqlite3

import pytest

from shared import anchored_attestation_replay as anchored
from shared.attestation_replay_registry import AttestationReplayRegistryError


GENESIS = "0" * 64
HEAD_1 = "1" * 64


class FakeAnchorStore:
    def __init__(self, *, provider_id="provider-a", sequence=0, head=GENESIS, available=True, cas_result=True):
        self.anchor = {
            "provider_id": provider_id,
            "sequence": sequence,
            "head_sha256": head,
        }
        self.available = available
        self.cas_result = cas_result
        self.cas_calls = []

    def get_anchor(self, provider_id):
        if not self.available:
            raise OSError("offline")
        return dict(self.anchor)

    def compare_and_set_anchor(
        self, provider_id, *, expected_sequence, expected_head_sha256,
        new_sequence, new_head_sha256,
    ):
        self.cas_calls.append((expected_sequence, expected_head_sha256, new_sequence, new_head_sha256))
        if not self.cas_result:
            return False
        if (self.anchor["sequence"], self.anchor["head_sha256"]) != (
            expected_sequence, expected_head_sha256
        ):
            return False
        self.anchor = {
            "provider_id": provider_id,
            "sequence": new_sequence,
            "head_sha256": new_head_sha256,
        }
        return True


def _db(path, sequence=0, head=GENESIS):
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE attestation_replay_journal_state "
            "(provider_id TEXT PRIMARY KEY, sequence INTEGER, head_sha256 TEXT)"
        )
        db.execute(
            "INSERT INTO attestation_replay_journal_state VALUES (?, ?, ?)",
            ("provider-a", sequence, head),
        )


def _record_stub(*args, database_path, **kwargs):
    with sqlite3.connect(database_path) as db:
        db.execute(
            "UPDATE attestation_replay_journal_state SET sequence=1, head_sha256=? "
            "WHERE provider_id=?",
            (HEAD_1, "provider-a"),
        )
    return {
        "journal": {"sequence": 1, "head_sha256": HEAD_1, "integrity_scope": "LOCAL_SQLITE_HASH_CHAIN_ONLY"},
        "qualification": "NOT_ESTABLISHED",
    }


def _call(path, store):
    return anchored.verify_and_record_attestation_anchored(
        {"runner": {"provider_id": "provider-a"}, "nonce": "n", "run_id": "r"},
        {},
        trusted_public_keys={},
        database_path=path,
        anchor_store=store,
    )


def test_anchored_registration_advances_external_anchor(monkeypatch, tmp_path):
    path = tmp_path / "registry.db"
    _db(path)
    store = FakeAnchorStore()
    monkeypatch.setattr(anchored, "verify_and_record_attestation", _record_stub)

    result = _call(path, store)

    assert store.anchor == {
        "provider_id": "provider-a", "sequence": 1, "head_sha256": HEAD_1
    }
    assert result["replay_protection"] == "LOCAL_REGISTRY_AND_EXTERNAL_MONOTONIC_ANCHOR"
    assert result["journal"]["rollback_resistance"] == "EXTERNAL_ANCHOR_CONFIRMED_FOR_RETURNED_HEAD"


def test_unavailable_external_anchor_fails_closed_before_recording(monkeypatch, tmp_path):
    path = tmp_path / "registry.db"
    _db(path)
    store = FakeAnchorStore(available=False)
    called = []
    monkeypatch.setattr(anchored, "verify_and_record_attestation", lambda *a, **k: called.append(True))

    with pytest.raises(AttestationReplayRegistryError, match="external_anchor_unavailable"):
        _call(path, store)
    assert called == []


def test_local_rollback_or_mismatch_fails_before_recording(monkeypatch, tmp_path):
    path = tmp_path / "registry.db"
    _db(path, sequence=3, head="3" * 64)
    store = FakeAnchorStore(sequence=4, head="4" * 64)
    called = []
    monkeypatch.setattr(anchored, "verify_and_record_attestation", lambda *a, **k: called.append(True))

    with pytest.raises(AttestationReplayRegistryError, match="local_registry_differs"):
        _call(path, store)
    assert called == []


def test_anchor_cas_conflict_does_not_report_success(monkeypatch, tmp_path):
    path = tmp_path / "registry.db"
    _db(path)
    store = FakeAnchorStore(cas_result=False)
    monkeypatch.setattr(anchored, "verify_and_record_attestation", _record_stub)

    with pytest.raises(AttestationReplayRegistryError, match="compare_and_set_conflict"):
        _call(path, store)
    assert store.anchor["sequence"] == 0


def test_anchor_rejects_wrong_provider_and_invalid_genesis(tmp_path):
    path = tmp_path / "registry.db"
    _db(path)
    store = FakeAnchorStore()
    store.anchor["provider_id"] = "other-provider"
    with pytest.raises(AttestationReplayRegistryError, match="provider_mismatch"):
        _call(path, store)

    store = FakeAnchorStore(head="f" * 64)
    with pytest.raises(AttestationReplayRegistryError, match="genesis_invalid"):
        _call(path, store)


def test_anchored_registration_uses_real_signed_receipt_and_journal(tmp_path):
    from test_attestation_replay_registry import _dossier, _envelope, _public_bytes
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    path = tmp_path / "real-registry.sqlite3"
    key = Ed25519PrivateKey.generate()
    dossier = _dossier("anchored-real-run", "anchored-real-nonce")
    envelope = _envelope(dossier, key)
    store = FakeAnchorStore(provider_id="test-provider")

    result = anchored.verify_and_record_attestation_anchored(
        dossier,
        envelope,
        trusted_public_keys={"pinned-runner-key": _public_bytes(key)},
        database_path=path,
        anchor_store=store,
    )

    assert result["valid"] is True
    assert result["journal"]["sequence"] == 1
    assert store.anchor["sequence"] == 1
    assert store.anchor["head_sha256"] == result["journal"]["head_sha256"]

    with pytest.raises(AttestationReplayRegistryError, match="local_registry_differs"):
        anchored.verify_and_record_attestation_anchored(
            _dossier("anchored-second-run", "anchored-second-nonce"),
            _envelope(_dossier("anchored-second-run", "anchored-second-nonce"), key),
            trusted_public_keys={"pinned-runner-key": _public_bytes(key)},
            database_path=path,
            anchor_store=FakeAnchorStore(provider_id="test-provider"),
        )


def test_post_commit_anchor_conflict_leaves_local_suffix_and_retry_fails_closed(tmp_path):
    from test_attestation_replay_registry import _dossier, _envelope, _public_bytes
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    path = tmp_path / "post-commit-conflict.sqlite3"
    key = Ed25519PrivateKey.generate()
    dossier = _dossier("post-commit-conflict-run", "post-commit-conflict-nonce")
    envelope = _envelope(dossier, key)
    store = FakeAnchorStore(provider_id="test-provider", cas_result=False)
    kwargs = {
        "trusted_public_keys": {"pinned-runner-key": _public_bytes(key)},
        "database_path": path,
        "anchor_store": store,
    }

    with pytest.raises(AttestationReplayRegistryError, match="compare_and_set_conflict_reconcile_required"):
        anchored.verify_and_record_attestation_anchored(dossier, envelope, **kwargs)

    with sqlite3.connect(path) as db:
        local_sequence, local_head = db.execute(
            "SELECT sequence, head_sha256 FROM attestation_replay_journal_state WHERE provider_id=?",
            ("test-provider",),
        ).fetchone()
        evidence_count = db.execute(
            "SELECT COUNT(*) FROM attestation_replay_evidence WHERE provider_id=?",
            ("test-provider",),
        ).fetchone()[0]

    assert local_sequence == 1
    assert local_head != GENESIS
    assert evidence_count == 1
    assert store.anchor["sequence"] == 0

    with pytest.raises(AttestationReplayRegistryError, match="local_registry_differs_from_external_anchor"):
        anchored.verify_and_record_attestation_anchored(dossier, envelope, **kwargs)
