"""Verify a signed runner receipt against an unsigned experiment dossier.

A passing result authenticates a configured signer's matching statement. It does
not prove runner independence, isolation, scientific validity, or key compromise.
"""
from __future__ import annotations

from typing import Mapping

from shared.experiment_dossier import (
    ExperimentDossierError,
    validate_experiment_dossier,
)
from shared.lab_execution_receipt import (
    LabExecutionReceiptError,
    verify_signed_receipt,
)


class IndependentRunnerAttestationError(ValueError):
    """Raised when a signed runner receipt does not bind to the dossier."""


def verify_independent_runner_attestation(
    dossier: dict,
    envelope: dict,
    *,
    trusted_public_keys: Mapping[str, bytes],
) -> dict:
    """Verify signature and exact dossier binding using out-of-band pinned keys.

    This is deliberately only a statement-binding check. It does not turn a
    self-described runner into an independently trusted execution environment.
    Replay prevention requires a separate durable run/nonce registry.
    """
    try:
        validate_experiment_dossier(dossier)
        verified = verify_signed_receipt(
            envelope, trusted_public_keys=trusted_public_keys
        )
    except (ExperimentDossierError, LabExecutionReceiptError) as exc:
        raise IndependentRunnerAttestationError(str(exc)) from exc

    receipt = envelope["receipt"]
    inputs = receipt["inputs"]
    execution = receipt["execution"]
    artifacts = receipt["artifacts"]

    expected_inputs = {
        "source_repository": dossier["source"]["repository"],
        "source_revision": dossier["source"]["revision"],
        "fixture_id": dossier["fixture"]["fixture_id"],
        "fixture_sha256": dossier["fixture"]["sha256"],
        "argv": dossier["command"]["argv"],
        "argv_sha256": dossier["command"]["argv_sha256"],
        "harness_sha256": dossier["harness"]["harness_sha256"],
        "build_recipe_sha256": dossier["harness"]["build_recipe_sha256"],
        "provider_id": dossier["runner"]["provider_id"],
        "runner_id": dossier["runner"]["runner_id"],
        "image_digest": dossier["runner"]["image_digest"],
        "nonce": dossier["nonce"],
        "safety": dossier["safety"],
    }
    for field, expected in expected_inputs.items():
        if inputs.get(field) != expected:
            raise IndependentRunnerAttestationError(f"attested_input_mismatch:{field}")

    if receipt["run_id"] != dossier["run_id"]:
        raise IndependentRunnerAttestationError("attested_run_id_mismatch")
    if receipt["experiment_id"] != dossier["experiment_id"]:
        raise IndependentRunnerAttestationError("attested_experiment_id_mismatch")

    expected_execution = {
        "started_at": dossier["execution"]["started_at"],
        "completed_at": dossier["execution"]["completed_at"],
        "exit_code": dossier["execution"]["exit_code"],
        "timed_out": dossier["execution"]["timed_out"],
        "test_passed": dossier["execution"]["test_passed"],
        "result_sha256": dossier["result_sha256"],
    }
    for field, expected in expected_execution.items():
        if execution.get(field) != expected:
            raise IndependentRunnerAttestationError(
                f"attested_execution_mismatch:{field}"
            )

    expected_artifacts = [
        {"name": item["name"], "sha256": item["sha256"]}
        for item in dossier["artifacts"]
    ]
    if artifacts.get("items") != expected_artifacts:
        raise IndependentRunnerAttestationError("attested_artifacts_mismatch")

    return {
        "valid": True,
        "key_id": verified["key_id"],
        "run_id": dossier["run_id"],
        "experiment_id": dossier["experiment_id"],
        "receipt_sha256": verified["receipt_sha256"],
        "input_binding": "MATCHED",
        "artifact_binding": "MATCHED",
        "runner_independence": "NOT_ESTABLISHED",
        "replay_protection": "NOT_ESTABLISHED",
        "qualification": "NOT_ESTABLISHED",
    }
