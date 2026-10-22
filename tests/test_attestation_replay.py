import hashlib
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
import zipfile

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared.attestation_replay import (
    SQLiteAttestationReplayRegistry,
    verify_bundle_execution_attestation_with_replay_protection,
    verify_execution_attestation_with_replay_protection,
)
from shared.execution_attestation import create_execution_attestation
from shared.local_experiment import build_experiment_record
from shared.local_experiment_bundle import export_local_experiment_bundle


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



def test_bundle_attestation_nonce_cannot_be_replayed(tmp_path):
    record, artifacts = build_experiment_record(
        case_id="replay-case-1",
        round_id="replay-round-1",
        task_id="replay-task-1",
        target_repository="example/protocol",
        target_commit="a" * 40,
        argv=["pytest", "-q"],
        toolchain={"python": "3.12.1"},
        input_bytes=b"fixture",
        stdout_bytes=b"control passed",
        stderr_bytes=b"",
        exit_code=0,
    )
    bundle = export_local_experiment_bundle(record, artifacts)
    attestation = create_execution_attestation(
        record=record,
        signer_id="trusted-signer",
        runner_id="runner-1",
        environment_sha256=hashlib.sha256(b"test-env").hexdigest(),
        issued_at="2026-10-19T10:00:00Z",
        nonce="bundle-nonce-1",
        private_key_bytes=PRIVATE_BYTES,
    )
    registry = SQLiteAttestationReplayRegistry(tmp_path / "bundle-replay.sqlite3")

    first = verify_bundle_execution_attestation_with_replay_protection(
        bundle,
        attestation,
        trusted_public_key_bytes=PUBLIC_BYTES,
        expected_signer_id="trusted-signer",
        replay_registry=registry,
    )
    second = verify_bundle_execution_attestation_with_replay_protection(
        bundle,
        attestation,
        trusted_public_key_bytes=PUBLIC_BYTES,
        expected_signer_id="trusted-signer",
        replay_registry=registry,
    )

    assert first["status"] == "PASS"
    assert first["bundle_integrity_verified"] is True
    assert first["attestation_verified"] is True
    assert first["replay_protection_verified"] is True
    assert second["status"] == "FAIL"
    assert second["bundle_integrity_verified"] is True
    assert second["attestation_verified"] is True
    assert second["replay_protection_verified"] is False
    assert second["errors"] == ["attestation_replay_detected"]



def test_concurrent_nonce_consumption_is_atomic(tmp_path):
    database = tmp_path / "concurrent-replay.sqlite3"

    def consume_once(_):
        # Independent registry instances model concurrent verifier requests
        # sharing one durable SQLite replay store.
        return SQLiteAttestationReplayRegistry(database).consume(
            "shared-signer", "one-time-nonce"
        )

    with ThreadPoolExecutor(max_workers=12) as pool:
        outcomes = list(pool.map(consume_once, range(24)))

    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 23



def test_concurrent_bundle_verification_accepts_attestation_once(tmp_path):
    record, artifacts = build_experiment_record(
        case_id="replay-concurrent-case",
        round_id="replay-concurrent-round",
        task_id="replay-concurrent-task",
        target_repository="example/protocol",
        target_commit="c" * 40,
        argv=["pytest", "-q"],
        toolchain={"python": "3.12.1"},
        input_bytes=b"fixture",
        stdout_bytes=b"control passed",
        stderr_bytes=b"",
        exit_code=0,
    )
    bundle = export_local_experiment_bundle(record, artifacts)
    attestation = create_execution_attestation(
        record=record,
        signer_id="trusted-signer",
        runner_id="runner-1",
        environment_sha256=hashlib.sha256(b"test-env").hexdigest(),
        issued_at="2026-10-19T10:00:00Z",
        nonce="concurrent-bundle-nonce",
        private_key_bytes=PRIVATE_BYTES,
    )
    database = tmp_path / "concurrent-bundle-replay.sqlite3"
    # Initialize the shared durable store before concurrent verifications.
    SQLiteAttestationReplayRegistry(database)

    def verify_once(_):
        return verify_bundle_execution_attestation_with_replay_protection(
            bundle,
            attestation,
            trusted_public_key_bytes=PUBLIC_BYTES,
            expected_signer_id="trusted-signer",
            replay_registry=SQLiteAttestationReplayRegistry(database),
        )

    with ThreadPoolExecutor(max_workers=12) as pool:
        reports = list(pool.map(verify_once, range(24)))

    assert sum(report["status"] == "PASS" for report in reports) == 1
    assert sum(report["status"] == "FAIL" for report in reports) == 23
    assert all(report["bundle_integrity_verified"] is True for report in reports)
    assert all(report["attestation_verified"] is True for report in reports)
    assert sum(report["replay_protection_verified"] is True for report in reports) == 1
    assert sum(
        report["errors"] == ["attestation_replay_detected"]
        for report in reports
    ) == 23



def test_invalid_bundle_does_not_consume_attestation_nonce(tmp_path):
    record, artifacts = build_experiment_record(
        case_id="replay-case-integrity",
        round_id="replay-round-integrity",
        task_id="replay-task-integrity",
        target_repository="example/protocol",
        target_commit="b" * 40,
        argv=["pytest", "-q"],
        toolchain={"python": "3.12.1"},
        input_bytes=b"fixture",
        stdout_bytes=b"control passed",
        stderr_bytes=b"",
        exit_code=0,
    )
    bundle = export_local_experiment_bundle(record, artifacts)
    attestation = create_execution_attestation(
        record=record,
        signer_id="trusted-signer",
        runner_id="runner-1",
        environment_sha256=hashlib.sha256(b"test-env").hexdigest(),
        issued_at="2026-10-19T10:00:00Z",
        nonce="integrity-nonce-1",
        private_key_bytes=PRIVATE_BYTES,
    )
    registry = SQLiteAttestationReplayRegistry(tmp_path / "integrity-replay.sqlite3")

    # Change a real ZIP member while leaving manifest.json unchanged.
    # Flipping the archive's final byte can alter ignored ZIP padding instead of
    # invalidating any evidence, so it is not a reliable tampering test.
    with zipfile.ZipFile(BytesIO(bundle), "r") as source:
        entries = [
            (info.filename, source.read(info.filename))
            for info in source.infolist()
        ]
    tampered_stream = BytesIO()
    with zipfile.ZipFile(
        tampered_stream, "w", compression=zipfile.ZIP_DEFLATED
    ) as target:
        for name, data in entries:
            if name == "stdout.bin":
                data += b"tampered"
            target.writestr(name, data)
    tampered_bundle = tampered_stream.getvalue()
    rejected = verify_bundle_execution_attestation_with_replay_protection(
        tampered_bundle,
        attestation,
        trusted_public_key_bytes=PUBLIC_BYTES,
        expected_signer_id="trusted-signer",
        replay_registry=registry,
    )
    accepted = verify_bundle_execution_attestation_with_replay_protection(
        bundle,
        attestation,
        trusted_public_key_bytes=PUBLIC_BYTES,
        expected_signer_id="trusted-signer",
        replay_registry=registry,
    )

    assert rejected["status"] == "FAIL"
    assert rejected["bundle_integrity_verified"] is False
    assert rejected["replay_protection_verified"] is False
    assert accepted["status"] == "PASS"
    assert accepted["bundle_integrity_verified"] is True
    assert accepted["replay_protection_verified"] is True
