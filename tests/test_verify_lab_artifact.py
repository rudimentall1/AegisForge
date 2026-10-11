import copy
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agents.lab_runner.agent import LabRunner
from shared.lab_execution_receipt import sign_receipt
from shared.verify_lab_artifact import main, verify_lab_artifact


def _experiment():
    return json.loads(json.dumps(LabRunner.run_synthetic_entropy_demo()))


def _public_bytes(private_key):
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def test_offline_verifier_accepts_integrity_consistent_unsigned_artifact():
    result = verify_lab_artifact(_experiment())

    assert result["integrity_verified"] is True
    assert result["successful_execution"] is True
    assert result["authenticity"] == "UNTRUSTED_UNSIGNED"
    assert result["signature_verified_against_trusted_key"] is False
    assert all(result["checks"].values())


def test_offline_verifier_detects_record_tampering():
    experiment = _experiment()
    experiment["execution_record"]["stdout"] += "tampered"

    result = verify_lab_artifact(experiment)

    assert result["integrity_verified"] is False
    assert result["checks"]["stdout_digest_matches"] is False
    assert result["checks"]["execution_matches_receipt"] is True


def test_offline_verifier_detects_command_and_result_tampering():
    changed_command = _experiment()
    changed_command["execution_record"]["command"][-1] = "print('tampered')"
    # Recompute the record's own digest to prove receipt binding is independently checked.
    import hashlib
    changed_command["execution_record"]["command_sha256"] = hashlib.sha256(
        json.dumps(
            changed_command["execution_record"]["command"],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    command_result = verify_lab_artifact(changed_command)
    assert command_result["integrity_verified"] is False
    assert command_result["checks"]["command_digest_matches"] is True
    assert command_result["checks"]["command_matches_receipt"] is False

    changed_payload = _experiment()
    changed_payload["execution_record"]["stdout"] = json.dumps(
        {"schema_version": 1, "synthetic_test_only": True}
    )
    changed_payload["execution_record"]["stdout_sha256"] = hashlib.sha256(
        changed_payload["execution_record"]["stdout"].encode("utf-8")
    ).hexdigest()
    payload_result = verify_lab_artifact(changed_payload)
    assert payload_result["integrity_verified"] is False
    assert payload_result["checks"]["result_payload_digest_matches"] is False


def test_offline_verifier_requires_explicit_trust_for_signed_artifact():
    experiment = _experiment()
    private_key = Ed25519PrivateKey.generate()
    experiment["execution_receipt_envelope"] = sign_receipt(
        experiment["execution_receipt"],
        private_key=private_key,
        key_id="test-runner",
    )

    untrusted = verify_lab_artifact(experiment)
    assert untrusted["integrity_verified"] is True
    assert untrusted["authenticity"] == "SIGNATURE_INVALID_OR_UNTRUSTED"

    trusted = verify_lab_artifact(
        experiment, {"test-runner": _public_bytes(private_key)}
    )
    assert trusted["integrity_verified"] is True
    assert trusted["authenticity"] == "SIGNED_AND_TRUSTED"
    assert trusted["signature_verified_against_trusted_key"] is True


def test_offline_verifier_cli_reports_invalid_artifact(tmp_path, capsys):
    experiment = _experiment()
    experiment["execution_record"]["stderr"] = "tampered"
    artifact_path = tmp_path / "experiment.json"
    artifact_path.write_text(json.dumps(experiment), encoding="utf-8")

    exit_code = main([str(artifact_path)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert json.loads(captured.out)["integrity_verified"] is False


def test_offline_verifier_cli_accepts_single_experiment_in_task_result(tmp_path, capsys):
    experiment = _experiment()
    artifact_path = tmp_path / "task-result.json"
    artifact_path.write_text(
        json.dumps({"lab_experiments": [experiment]}), encoding="utf-8"
    )

    exit_code = main([str(artifact_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    result = json.loads(captured.out)
    assert result["integrity_verified"] is True
    assert result["authenticity"] == "UNTRUSTED_UNSIGNED"
