import hashlib
import sqlite3

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared.attestation_replay_registry import AttestationReplayRegistryError, verify_and_record_attestation
from shared.experiment_dossier import canonical_json
from shared.lab_execution_receipt import build_receipt, sign_receipt


def _sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _dossier(run_id="run-replay-test-001", nonce="nonce-replay-test-001"):
    argv = ["python", "-m", "pytest", "tests/test_synthetic_fixture.py", "-q"]
    return {
        "schema_version": "evm-key-forensics-experiment-dossier-v1",
        "experiment_id": "synthetic-source-check-v1", "run_id": run_id, "nonce": nonce,
        "source": {"repository": "https://github.com/rudimentall1/AegisForge", "revision": "a" * 40},
        "fixture": {"fixture_id": "fixture-synthetic-001", "sha256": _sha("fixture")},
        "command": {"argv": argv, "argv_sha256": _sha(canonical_json(argv))},
        "harness": {"harness_sha256": _sha("harness"), "build_recipe_sha256": _sha("build recipe")},
        "runner": {"provider_id": "test-provider", "runner_id": "runner-01", "image_digest": None},
        "execution": {"started_at": "2026-10-12T06:00:00Z", "completed_at": "2026-10-12T06:00:03Z", "exit_code": 0, "timed_out": False, "test_passed": True},
        "result_sha256": _sha("result"),
        "artifacts": [{"name": "result.json", "sha256": _sha("artifact")}],
        "safety": {"scope": "synthetic_only", "historical_code_executed": False, "real_key_material_handled": False},
    }


def _public_bytes(key):
    return key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def _envelope(dossier, key):
    receipt = build_receipt(
        run_id=dossier["run_id"], experiment_id=dossier["experiment_id"],
        inputs={
            "source_repository": dossier["source"]["repository"], "source_revision": dossier["source"]["revision"],
            "fixture_id": dossier["fixture"]["fixture_id"], "fixture_sha256": dossier["fixture"]["sha256"],
            "argv": dossier["command"]["argv"], "argv_sha256": dossier["command"]["argv_sha256"],
            "harness_sha256": dossier["harness"]["harness_sha256"], "build_recipe_sha256": dossier["harness"]["build_recipe_sha256"],
            "provider_id": dossier["runner"]["provider_id"], "runner_id": dossier["runner"]["runner_id"],
            "image_digest": dossier["runner"]["image_digest"], "nonce": dossier["nonce"], "safety": dossier["safety"],
        },
        execution={
            "started_at": dossier["execution"]["started_at"], "completed_at": dossier["execution"]["completed_at"],
            "exit_code": dossier["execution"]["exit_code"], "timed_out": dossier["execution"]["timed_out"],
            "test_passed": dossier["execution"]["test_passed"], "result_sha256": dossier["result_sha256"],
        },
        artifacts={"items": [{"name": item["name"], "sha256": item["sha256"]} for item in dossier["artifacts"]]},
    )
    return sign_receipt(receipt, private_key=key, key_id="pinned-runner-key")


def _accept(dossier, envelope, key, path):
    return verify_and_record_attestation(dossier, envelope, trusted_public_keys={"pinned-runner-key": _public_bytes(key)}, database_path=path)


def test_first_valid_attestation_is_recorded_and_stays_unqualified(tmp_path):
    dossier, key = _dossier(), Ed25519PrivateKey.generate()
    result = _accept(dossier, _envelope(dossier, key), key, tmp_path / "registry.sqlite3")
    assert result["replay_protection"] == "RECORDED_ONCE_IN_LOCAL_SQLITE_REGISTRY"
    assert result["qualification"] == "NOT_ESTABLISHED"


def test_same_receipt_replay_is_rejected(tmp_path):
    dossier, key, path = _dossier(), Ed25519PrivateKey.generate(), tmp_path / "registry.sqlite3"
    envelope = _envelope(dossier, key)
    _accept(dossier, envelope, key, path)
    with pytest.raises(AttestationReplayRegistryError, match="attestation_replay_detected"):
        _accept(dossier, envelope, key, path)


def test_nonce_reuse_with_different_run_id_is_rejected(tmp_path):
    key, path = Ed25519PrivateKey.generate(), tmp_path / "registry.sqlite3"
    first, second = _dossier("run-one", "shared-nonce"), _dossier("run-two", "shared-nonce")
    _accept(first, _envelope(first, key), key, path)
    with pytest.raises(AttestationReplayRegistryError, match="attestation_replay_detected"):
        _accept(second, _envelope(second, key), key, path)


def test_distinct_run_and_nonce_are_accepted(tmp_path):
    key, path = Ed25519PrivateKey.generate(), tmp_path / "registry.sqlite3"
    first, second = _dossier("run-one", "nonce-one"), _dossier("run-two", "nonce-two")
    assert _accept(first, _envelope(first, key), key, path)["valid"]
    assert _accept(second, _envelope(second, key), key, path)["valid"]


def test_invalid_signature_does_not_reserve_nonce(tmp_path):
    dossier, key, path = _dossier(), Ed25519PrivateKey.generate(), tmp_path / "registry.sqlite3"
    invalid = _envelope(dossier, key)
    invalid["signature"] = "AAAA"
    with pytest.raises(AttestationReplayRegistryError, match="attestation_invalid"):
        _accept(dossier, invalid, key, path)
    assert _accept(dossier, _envelope(dossier, key), key, path)["valid"]


def test_database_failure_fails_closed(tmp_path):
    dossier, key = _dossier(), Ed25519PrivateKey.generate()
    path = tmp_path / "not-a-database-dir"
    path.mkdir()
    with pytest.raises(AttestationReplayRegistryError, match="replay_registry_unavailable_fail_closed"):
        _accept(dossier, _envelope(dossier, key), key, path)


def test_registry_records_receipt_hash_and_identity(tmp_path):
    dossier, key, path = _dossier(), Ed25519PrivateKey.generate(), tmp_path / "registry.sqlite3"
    envelope = _envelope(dossier, key)
    result = _accept(dossier, envelope, key, path)
    with sqlite3.connect(path) as db:
        row = db.execute("SELECT provider_id, key_id, run_id, nonce, receipt_sha256 FROM accepted_runner_attestations").fetchone()
    assert row == ("test-provider", "pinned-runner-key", dossier["run_id"], dossier["nonce"], result["receipt_sha256"])


def test_concurrent_duplicate_attestation_has_exactly_one_winner(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    dossier, key, path = _dossier(), Ed25519PrivateKey.generate(), tmp_path / "registry.sqlite3"
    envelope = _envelope(dossier, key)
    barrier = Barrier(2)

    def attempt():
        barrier.wait(timeout=5)
        try:
            _accept(dossier, envelope, key, path)
            return "accepted"
        except AttestationReplayRegistryError as exc:
            if "attestation_replay_detected" in str(exc):
                return "replay"
            raise

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: attempt(), range(2)))

    assert sorted(outcomes) == ["accepted", "replay"]
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM accepted_runner_attestations").fetchone()[0] == 1


def test_nonce_namespace_is_provider_scoped_across_real_key_rotation(tmp_path):
    old_key, new_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    path = tmp_path / "registry.sqlite3"
    first = _dossier("run-before-rotation", "nonce-across-rotation")
    _accept(first, _envelope(first, old_key), old_key, path)

    # The second receipt is signed by different key material. Reusing the
    # provider nonce must still fail; rotation does not reset replay state.
    second = _dossier("run-after-rotation", "nonce-across-rotation")
    second_envelope = _envelope(second, new_key)
    with pytest.raises(AttestationReplayRegistryError, match="attestation_replay_detected"):
        verify_and_record_attestation(
            second, second_envelope,
            trusted_public_keys={"pinned-runner-key": _public_bytes(new_key)},
            database_path=path,
        )


def test_distinct_nonce_is_accepted_after_real_key_rotation(tmp_path):
    old_key, new_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    path = tmp_path / "registry.sqlite3"
    first = _dossier("run-before-rotation", "nonce-before-rotation")
    _accept(first, _envelope(first, old_key), old_key, path)

    second = _dossier("run-after-rotation", "nonce-after-rotation")
    result = verify_and_record_attestation(
        second, _envelope(second, new_key),
        trusted_public_keys={"pinned-runner-key": _public_bytes(new_key)},
        database_path=path,
    )
    assert result["valid"]



def test_successful_acceptance_advances_hash_chain_atomically(tmp_path):
    key, path = Ed25519PrivateKey.generate(), tmp_path / "registry.sqlite3"
    first = _dossier("journal-run-one", "journal-nonce-one")
    second = _dossier("journal-run-two", "journal-nonce-two")
    result_one = _accept(first, _envelope(first, key), key, path)
    result_two = _accept(second, _envelope(second, key), key, path)

    assert result_one["journal"]["sequence"] == 1
    assert result_two["journal"]["sequence"] == 2
    assert result_one["journal"]["head_sha256"] != result_two["journal"]["head_sha256"]
    with sqlite3.connect(path) as db:
        accepted = db.execute("SELECT COUNT(*) FROM accepted_runner_attestations").fetchone()[0]
        journal = db.execute(
            "SELECT sequence, head_sha256 FROM attestation_replay_journal_state WHERE provider_id = ?",
            ("test-provider",),
        ).fetchone()
        events = db.execute(
            "SELECT sequence, previous_head_sha256, head_sha256 FROM attestation_replay_journal ORDER BY sequence"
        ).fetchall()
    assert accepted == 2
    assert journal == (2, result_two["journal"]["head_sha256"])
    assert events[0][0] == 1
    assert events[0][1] == "0" * 64
    assert events[0][2] == events[1][1]
    assert events[1][0] == 2


def test_replayed_attestation_does_not_advance_journal(tmp_path):
    key, path = Ed25519PrivateKey.generate(), tmp_path / "registry.sqlite3"
    dossier = _dossier("journal-replay", "journal-replay-nonce")
    envelope = _envelope(dossier, key)
    first = _accept(dossier, envelope, key, path)
    with pytest.raises(AttestationReplayRegistryError, match="attestation_replay_detected"):
        _accept(dossier, envelope, key, path)
    with sqlite3.connect(path) as db:
        state = db.execute(
            "SELECT sequence, head_sha256 FROM attestation_replay_journal_state WHERE provider_id = ?",
            ("test-provider",),
        ).fetchone()
        count = db.execute("SELECT COUNT(*) FROM attestation_replay_journal").fetchone()[0]
    assert state == (1, first["journal"]["head_sha256"])
    assert count == 1


def test_legacy_registry_with_accepted_rows_fails_closed_without_journal_migration(tmp_path):
    key, path = Ed25519PrivateKey.generate(), tmp_path / "legacy.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("""
            CREATE TABLE accepted_runner_attestations (
                provider_id TEXT NOT NULL, key_id TEXT NOT NULL, run_id TEXT NOT NULL,
                nonce TEXT NOT NULL, receipt_sha256 TEXT NOT NULL,
                first_seen_at TEXT NOT NULL DEFAULT 'legacy',
                PRIMARY KEY(provider_id, run_id), UNIQUE(provider_id, nonce)
            )
        """)
        db.execute(
            "INSERT INTO accepted_runner_attestations(provider_id, key_id, run_id, nonce, receipt_sha256) VALUES (?, ?, ?, ?, ?)",
            ("test-provider", "old-key", "legacy-run", "legacy-nonce", _sha("legacy receipt")),
        )
    dossier = _dossier("after-legacy", "after-legacy-nonce")
    with pytest.raises(AttestationReplayRegistryError, match="legacy_state_requires_migration"):
        _accept(dossier, _envelope(dossier, key), key, path)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM accepted_runner_attestations").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM attestation_replay_journal").fetchone()[0] == 0
