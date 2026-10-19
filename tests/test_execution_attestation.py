import copy
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared.execution_attestation import (
    create_execution_attestation,
    verify_execution_attestation,
)


PRIVATE_BYTES = b"\x11" * 32
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(PRIVATE_BYTES)
PUBLIC_BYTES = PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
RECORD = {
    "schema_version": "aegisforge-local-experiment-v1",
    "case_id": "case-attest-1",
    "round_id": "round-attest-1",
    "task_id": "task-attest-1",
    "target_repository": "example/protocol",
    "target_commit": "a" * 40,
    "argv": ["pytest", "-q"],
    "toolchain": {"python": "3.12.1"},
    "exit_code": 0,
    "expected_exit_code": 0,
    "status": "PASS",
    "artifacts": {},
}


def _attestation(**overrides):
    values = {
        "record": RECORD,
        "signer_id": "ci-runner-key-1",
        "runner_id": "runner-linux-x64-1",
        "environment_sha256": hashlib.sha256(b"pinned test image").hexdigest(),
        "issued_at": "2026-10-19T10:00:00Z",
        "nonce": "job-123-attempt-1",
        "private_key_bytes": PRIVATE_BYTES,
    }
    values.update(overrides)
    return create_execution_attestation(**values)


def test_ed25519_attestation_verifies_against_explicit_trusted_key():
    attestation = _attestation()
    report = verify_execution_attestation(
        attestation,
        trusted_public_key_bytes=PUBLIC_BYTES,
        expected_signer_id="ci-runner-key-1",
        expected_record=RECORD,
    )

    assert report["status"] == "PASS"
    assert report["attestation_verified"] is True
    assert report["execution_truth_established"] is False
    assert report["runner_compromise_ruled_out"] is False
    assert report["record_sha256"] == hashlib.sha256(
        __import__("json").dumps(
            RECORD, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def test_attestation_rejects_modified_signed_claims():
    attestation = _attestation()
    changed = copy.deepcopy(attestation)
    changed["claims"]["runner_id"] = "attacker-controlled-runner"

    report = verify_execution_attestation(
        changed,
        trusted_public_key_bytes=PUBLIC_BYTES,
        expected_signer_id="ci-runner-key-1",
        expected_record=RECORD,
    )
    assert report["status"] == "FAIL"
    assert report["errors"] == ["attestation_signature_invalid"]
    assert report["execution_truth_established"] is False


def test_attestation_rejects_wrong_trusted_public_key():
    wrong_public = Ed25519PrivateKey.from_private_bytes(b"\x22" * 32).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    report = verify_execution_attestation(
        _attestation(),
        trusted_public_key_bytes=wrong_public,
        expected_signer_id="ci-runner-key-1",
        expected_record=RECORD,
    )
    assert report["status"] == "FAIL"
    assert report["errors"] == ["attestation_signature_invalid"]


def test_attestation_rejects_unexpected_signer_identity():
    report = verify_execution_attestation(
        _attestation(),
        trusted_public_key_bytes=PUBLIC_BYTES,
        expected_signer_id="different-trusted-key",
        expected_record=RECORD,
    )
    assert report["status"] == "FAIL"
    assert report["errors"] == ["attestation_signer_identity_mismatch"]


def test_attestation_binds_exact_experiment_record_digest():
    changed_record = dict(RECORD)
    changed_record["target_commit"] = "b" * 40
    report = verify_execution_attestation(
        _attestation(),
        trusted_public_key_bytes=PUBLIC_BYTES,
        expected_signer_id="ci-runner-key-1",
        expected_record=changed_record,
    )
    assert report["status"] == "FAIL"
    assert report["errors"] == ["attestation_record_digest_mismatch"]


def test_attestation_rejects_malformed_envelope_and_key():
    assert verify_execution_attestation(
        {"claims": {}},
        trusted_public_key_bytes=PUBLIC_BYTES,
        expected_signer_id="ci-runner-key-1",
    )["errors"] == ["attestation_envelope_invalid"]
    assert verify_execution_attestation(
        _attestation(),
        trusted_public_key_bytes=b"short",
        expected_signer_id="ci-runner-key-1",
    )["errors"] == ["trusted_ed25519_public_key_must_be_32_bytes"]



def test_bundle_attestation_checks_bundle_and_exact_embedded_record():
    record, artifacts = build_experiment_record(
        case_id="case-attest-1",
        round_id="round-attest-1",
        task_id="task-attest-1",
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
    attestation = _attestation(record=record)
    report = verify_bundle_execution_attestation(
        bundle,
        attestation,
        trusted_public_key_bytes=PUBLIC_BYTES,
        expected_signer_id="ci-runner-key-1",
    )

    assert report["status"] == "PASS"
    assert report["bundle_integrity_verified"] is True
    assert report["attestation_verified"] is True
    assert report["execution_truth_established"] is False


def test_bundle_attestation_refuses_tampered_bundle():
    report = verify_bundle_execution_attestation(
        b"not a zip",
        _attestation(),
        trusted_public_key_bytes=PUBLIC_BYTES,
        expected_signer_id="ci-runner-key-1",
    )
    assert report["status"] == "FAIL"
    assert report["bundle_integrity_verified"] is False
    assert report["errors"] == ["experiment_bundle_integrity_not_verified"]
