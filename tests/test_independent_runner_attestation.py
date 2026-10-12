import copy
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared.experiment_dossier import canonical_json
from shared.independent_runner_attestation import (
    IndependentRunnerAttestationError,
    verify_independent_runner_attestation,
)
from shared.lab_execution_receipt import build_receipt, sign_receipt


def _sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _dossier():
    argv = ["python", "-m", "pytest", "tests/test_synthetic_fixture.py", "-q"]
    return {
        "schema_version": "evm-key-forensics-experiment-dossier-v1",
        "experiment_id": "synthetic-source-check-v1",
        "run_id": "run-synthetic-0001",
        "nonce": "operator-supplied-unique-nonce-0001",
        "source": {
            "repository": "https://github.com/rudimentall1/AegisForge",
            "revision": "a" * 40,
        },
        "fixture": {"fixture_id": "fixture-synthetic-001", "sha256": _sha("fixture")},
        "command": {"argv": argv, "argv_sha256": _sha(canonical_json(argv))},
        "harness": {"harness_sha256": _sha("harness"), "build_recipe_sha256": _sha("build recipe")},
        "runner": {"provider_id": "test-provider", "runner_id": "runner-01", "image_digest": None},
        "execution": {
            "started_at": "2026-10-12T06:00:00Z",
            "completed_at": "2026-10-12T06:00:03Z",
            "exit_code": 0,
            "timed_out": False,
            "test_passed": True,
        },
        "result_sha256": _sha("result"),
        "artifacts": [{"name": "result.json", "sha256": _sha("artifact")}],
        "safety": {
            "scope": "synthetic_only",
            "historical_code_executed": False,
            "real_key_material_handled": False,
        },
    }


def _envelope(dossier, key, *, source_revision=None):
    argv = dossier["command"]["argv"]
    receipt = build_receipt(
        run_id=dossier["run_id"],
        experiment_id=dossier["experiment_id"],
        inputs={
            "source_repository": dossier["source"]["repository"],
            "source_revision": source_revision or dossier["source"]["revision"],
            "fixture_id": dossier["fixture"]["fixture_id"],
            "fixture_sha256": dossier["fixture"]["sha256"],
            "argv": argv,
            "argv_sha256": dossier["command"]["argv_sha256"],
            "harness_sha256": dossier["harness"]["harness_sha256"],
            "build_recipe_sha256": dossier["harness"]["build_recipe_sha256"],
            "provider_id": dossier["runner"]["provider_id"],
            "runner_id": dossier["runner"]["runner_id"],
            "image_digest": dossier["runner"]["image_digest"],
            "nonce": dossier["nonce"],
            "safety": dossier["safety"],
        },
        execution={
            "started_at": dossier["execution"]["started_at"],
            "completed_at": dossier["execution"]["completed_at"],
            "exit_code": dossier["execution"]["exit_code"],
            "timed_out": dossier["execution"]["timed_out"],
            "test_passed": dossier["execution"]["test_passed"],
            "result_sha256": dossier["result_sha256"],
        },
        artifacts={"items": [
            {"name": item["name"], "sha256": item["sha256"]}
            for item in dossier["artifacts"]
        ]},
    )
    return sign_receipt(receipt, private_key=key, key_id="pinned-runner-key")


def _public_bytes(key):
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def test_signed_runner_receipt_binds_exact_dossier_but_does_not_qualify():
    dossier = _dossier()
    key = Ed25519PrivateKey.generate()
    result = verify_independent_runner_attestation(
        dossier, _envelope(dossier, key),
        trusted_public_keys={"pinned-runner-key": _public_bytes(key)},
    )
    assert result["valid"] is True
    assert result["input_binding"] == "MATCHED"
    assert result["artifact_binding"] == "MATCHED"
    assert result["runner_independence"] == "NOT_ESTABLISHED"
    assert result["qualification"] == "NOT_ESTABLISHED"


def test_signed_receipt_for_different_source_revision_is_rejected():
    dossier = _dossier()
    key = Ed25519PrivateKey.generate()
    envelope = _envelope(dossier, key, source_revision="b" * 40)
    with pytest.raises(IndependentRunnerAttestationError, match="attested_input_mismatch:source_revision"):
        verify_independent_runner_attestation(
            dossier, envelope,
            trusted_public_keys={"pinned-runner-key": _public_bytes(key)},
        )


def test_signed_receipt_for_different_artifact_is_rejected():
    dossier = _dossier()
    key = Ed25519PrivateKey.generate()
    envelope = _envelope(dossier, key)
    envelope["receipt"]["artifacts"]["items"][0]["sha256"] = _sha("other artifact")
    # The receipt is now tampered with; recomputing its digest cannot repair its signature.
    from shared.lab_execution_receipt import receipt_sha256
    envelope["receipt_sha256"] = receipt_sha256(envelope["receipt"])
    with pytest.raises(IndependentRunnerAttestationError, match="receipt_signature_invalid"):
        verify_independent_runner_attestation(
            dossier, envelope,
            trusted_public_keys={"pinned-runner-key": _public_bytes(key)},
        )


def test_unknown_runner_key_is_rejected():
    dossier = _dossier()
    key = Ed25519PrivateKey.generate()
    with pytest.raises(IndependentRunnerAttestationError, match="untrusted_runner_key"):
        verify_independent_runner_attestation(
            dossier, _envelope(dossier, key), trusted_public_keys={}
        )


def test_run_id_mismatch_is_rejected_even_when_receipt_is_signed():
    dossier = _dossier()
    key = Ed25519PrivateKey.generate()
    envelope = _envelope(dossier, key)
    envelope["receipt"]["run_id"] = "different-run"
    from shared.lab_execution_receipt import receipt_sha256
    envelope["receipt_sha256"] = receipt_sha256(envelope["receipt"])
    with pytest.raises(IndependentRunnerAttestationError, match="receipt_signature_invalid"):
        verify_independent_runner_attestation(
            dossier, envelope,
            trusted_public_keys={"pinned-runner-key": _public_bytes(key)},
        )
