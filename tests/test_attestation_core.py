"""Security-focused tests for the portable attestation core."""
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared.attestation import (
    AttestationError,
    canonical_json,
    sign_attestation,
    verify_attestation,
)


def _inputs(artifacts=None):
    return {
        "case_ref": {
            "case_id": "case-test-001",
            "case_digest": hashlib.sha256(b"case").hexdigest(),
            "target_repository": "example/project",
            "target_commit": "a" * 40,
            "scope_url": "https://example.invalid/scope",
            "scope_digest": hashlib.sha256(b"scope").hexdigest(),
        },
        "finding_ref": {
            "finding_id": "finding-test-001",
            "claim": "A bounded test claim",
            "affected_component": "example-component",
            "source_locations": [],
            "impact_path": "test-only",
        },
        "reproduction": {
            "reproduction_contract_sha256": hashlib.sha256(b"contract").hexdigest(),
            "commands": [["python", "-V"]],
            "environment": {"python": "3.x"},
            "network_access": False,
            "artifacts": artifacts or [],
            "started_at": "2026-10-16T10:00:00+00:00",
            "completed_at": "2026-10-16T10:00:01+00:00",
            "exit_code": 0,
        },
        "verdict": "REPRODUCED",
        "verdict_rationale": "The bounded local reproduction completed.",
    }


def _signed(private_key=None, artifacts=None, verdict="REPRODUCED"):
    key = private_key or Ed25519PrivateKey.generate()
    inputs = _inputs(artifacts)
    inputs["verdict"] = verdict
    attestation = sign_attestation(
        **inputs,
        private_key=key,
        key_id="test-key",
        organization="AegisForge test suite",
        issued_at="2026-10-16T10:00:02+00:00",
    )
    return attestation.to_dict(), key


def test_sign_and_verify_round_trip():
    payload, key = _signed()
    public_key = key.public_key()
    result = verify_attestation(payload, trusted_keys={"test-key": public_key})

    assert result.status == "VALID"
    assert result.reason == "ok"
    assert result.checks["signature_valid"] is True


def test_modified_payload_is_rejected():
    payload, key = _signed()
    payload["verdict_rationale"] = "modified after signing"

    result = verify_attestation(
        payload, trusted_keys={"test-key": key.public_key()}
    )

    assert result.status == "TAMPERED"


def test_unknown_signer_is_untrusted():
    payload, _ = _signed()

    result = verify_attestation(payload, trusted_keys={})

    assert result.status == "UNTRUSTED"
    assert result.reason == "untrusted_key"


def test_confirmed_verdict_is_never_accepted():
    with pytest.raises(AttestationError, match="verdict_not_allowed"):
        _signed(verdict="CONFIRMED")


def test_artifact_digest_and_size_are_verified(tmp_path: Path):
    artifact = b"reproducible test evidence\n"
    (tmp_path / "evidence.txt").write_bytes(artifact)
    entry = {
        "path": "evidence.txt",
        "sha256": hashlib.sha256(artifact).hexdigest(),
        "size_bytes": len(artifact),
    }
    payload, key = _signed(artifacts=[entry])

    result = verify_attestation(
        payload,
        trusted_keys={"test-key": key.public_key()},
        artifact_root=tmp_path,
    )
    assert result.status == "VALID"
    assert result.checks["artifacts_valid"] is True


def test_artifact_traversal_fails_closed(tmp_path: Path):
    payload, key = _signed(
        artifacts=[{
            "path": "../outside.txt",
            "sha256": hashlib.sha256(b"x").hexdigest(),
            "size_bytes": 1,
        }]
    )

    result = verify_attestation(
        payload,
        trusted_keys={"test-key": key.public_key()},
        artifact_root=tmp_path,
    )

    assert result.status == "INVALID"
    assert result.reason == "artifact_path_outside_root"
    assert result.checks["artifacts_path_safe"] is False
    assert result.checks["artifacts_valid"] is False


def test_expected_case_digest_mismatch_is_rejected():
    payload, key = _signed()

    result = verify_attestation(
        payload,
        trusted_keys={"test-key": key.public_key()},
        expected_case_digest=hashlib.sha256(b"different case").hexdigest(),
    )

    assert result.status == "INVALID"
    assert result.reason == "case_digest_mismatch"
    assert result.checks["case_digest_matches"] is False


def test_canonical_json_rejects_non_finite_numbers():
    with pytest.raises(AttestationError, match="value_not_canonical_json_serializable"):
        canonical_json({"unsafe": float("nan")})


def test_tampered_artifact_content_is_rejected(tmp_path: Path):
    (tmp_path / "evidence.txt").write_bytes(b"changed")
    entry = {
        "path": "evidence.txt",
        "sha256": hashlib.sha256(b"original").hexdigest(),
        "size_bytes": len(b"original"),
    }
    payload, key = _signed(artifacts=[entry])

    result = verify_attestation(
        payload,
        trusted_keys={"test-key": key.public_key()},
        artifact_root=tmp_path,
    )

    assert result.status == "TAMPERED"
    assert result.reason == "artifact_mismatch"
    assert result.checks["artifacts_valid"] is False
