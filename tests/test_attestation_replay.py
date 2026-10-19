import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared.attestation_replay import (
    SQLiteAttestationReplayRegistry,
    verify_execution_attestation_with_replay_protection,
)
from shared.execution_attestation import create_execution_attestation


PRIVATE_BYTES = bytes([0x31]) * 32
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(PRIVATE_BYTES)
PUBLIC_BYTES = PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
RECORD = {
    "case_id": "replay-case-1",
    "round_id": "replay-round-1",
    "task_id": "replay-task-1",
    "target_repository": "example/protocol",
    "target_commit": "a" * 40,
}


def make_attestation(*, nonce="nonce-1", signer_id="trusted-signer"):
    return create_execution_attestation(
        record=RECORD,
        signer_id=signer_id,
        runner_id="runner-1",
        environment_sha256=hashlib.sha256(b"test-env").hexdigest(),
        issued_at="2026-10-19T10:00:00Z",
        nonce=nonce,
        private_key_bytes=PRIVATE_BYTES,
    )


def verify(attestation, registry):
    return verify_execution_attestation_with_replay_protection(
        attestation,
        trusted_public_key_bytes=PUBLIC_BYTES,
        expected_signer_id="trusted-signer",
        replay_registry=registry,
    )


def test_sqlite_registry_accepts_nonce_once_and_persists(tmp_path):
    database = tmp_path / "replay.sqlite3"
    first_process = SQLiteAttestationReplayRegistry(database)
    assert first_process.consume("signer", "nonce") is True

    second_process = SQLiteAttestationReplayRegistry(database)
    assert second_process.consume("signer", "nonce") is False
    assert second_process.consume("signer", "different-nonce") is True
    assert second_process.consume("different-signer", "nonce") is True


def test_verified_attestation_nonce_cannot_be_replayed(tmp_path):
    registry = SQLiteAttestationReplayRegistry(tmp_path / "replay.sqlite3")
    attestation = make_attestation()

    first = verify(attestation, registry)
    second = verify(attestation, registry)

    assert first["status"] == "PASS"
    assert first["attestation_verified"] is True
    assert first["replay_protection_verified"] is True
    assert second["status"] == "FAIL"
    assert second["attestation_verified"] is True
    assert second["replay_protection_verified"] is False
    assert second["errors"] == ["attestation_replay_detected"]
    assert second["execution_truth_established"] is False


def test_invalid_signature_does_not_consume_nonce(tmp_path):
    registry = SQLiteAttestationReplayRegistry(tmp_path / "replay.sqlite3")
    attestation = make_attestation()
    attestation["claims"]["runner_id"] = "tampered-runner"

    rejected = verify(attestation, registry)
    assert rejected["status"] == "FAIL"
    assert rejected["replay_protection_verified"] is False
    assert registry.consume("trusted-signer", "nonce-1") is True


def test_registry_failure_fails_closed(tmp_path):
    registry = SQLiteAttestationReplayRegistry(tmp_path / "replay.sqlite3")

    class BrokenRegistry:
        def consume(self, signer_id, nonce):
            raise OSError("store unavailable")

    report = verify(make_attestation(), BrokenRegistry())
    assert report["status"] == "FAIL"
    assert report["attestation_verified"] is True
    assert report["replay_protection_verified"] is False
    assert report["errors"] == ["attestation_replay_registry_unavailable"]


def test_registry_rejects_ephemeral_database():
    with pytest.raises(ValueError, match="durable_database_path"):
        SQLiteAttestationReplayRegistry(":memory:")
