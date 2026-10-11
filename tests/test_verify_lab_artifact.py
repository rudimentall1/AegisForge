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


def test_offline_verifier_cli_reports_unsigned_artifact_as_untrusted(tmp_path, capsys):
    experiment = _experiment()
    artifact_path = tmp_path / "task-result.json"
    artifact_path.write_text(
        json.dumps({"lab_experiments": [experiment]}), encoding="utf-8"
    )

    exit_code = main([str(artifact_path)])
    captured = capsys.readouterr()

    # Exit 0 is reserved for artifacts verified against an explicitly trusted key.
    assert exit_code == 2
    result = json.loads(captured.out)
    assert result["integrity_verified"] is True
    assert result["authenticity"] == "UNTRUSTED_UNSIGNED"



def test_offline_verifier_cli_returns_success_only_for_trusted_signature(tmp_path, capsys):
    experiment = _experiment()
    private_key = Ed25519PrivateKey.generate()
    experiment["execution_receipt_envelope"] = sign_receipt(
        experiment["execution_receipt"],
        private_key=private_key,
        key_id="trusted-runner",
    )
    artifact_path = tmp_path / "signed-experiment.json"
    artifact_path.write_text(json.dumps(experiment), encoding="utf-8")
    public_key_path = tmp_path / "trusted-runner.pub"
    public_key_path.write_bytes(_public_bytes(private_key))

    exit_code = main([
        str(artifact_path),
        "--trusted-key",
        f"trusted-runner={public_key_path}",
    ])
    captured = capsys.readouterr()

    assert exit_code == 0
    result = json.loads(captured.out)
    assert result["integrity_verified"] is True
    assert result["authenticity"] == "SIGNED_AND_TRUSTED"
    assert result["signature_verified_against_trusted_key"] is True



def test_offline_verifier_cli_rejects_wrong_trusted_key(tmp_path, capsys):
    experiment = _experiment()
    signing_key = Ed25519PrivateKey.generate()
    unrelated_key = Ed25519PrivateKey.generate()
    experiment["execution_receipt_envelope"] = sign_receipt(
        experiment["execution_receipt"],
        private_key=signing_key,
        key_id="runner-key",
    )
    artifact_path = tmp_path / "signed-experiment.json"
    artifact_path.write_text(json.dumps(experiment), encoding="utf-8")
    trusted_key_path = tmp_path / "wrong.pub"
    trusted_key_path.write_bytes(_public_bytes(unrelated_key))

    exit_code = main([
        str(artifact_path),
        "--trusted-key",
        f"runner-key={trusted_key_path}",
    ])
    captured = capsys.readouterr()

    assert exit_code == 2
    result = json.loads(captured.out)
    assert result["integrity_verified"] is True
    assert result["authenticity"] == "SIGNATURE_INVALID_OR_UNTRUSTED"
    assert result["signature_verified_against_trusted_key"] is False


def test_offline_verifier_cli_rejects_duplicate_json_keys(tmp_path, capsys):
    artifact_path = tmp_path / "duplicate-key.json"
    artifact_path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")

    exit_code = main([str(artifact_path)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert json.loads(captured.err)["error"] == "duplicate_json_key:schema_version"


def test_offline_verifier_cli_rejects_nonstandard_json_numbers(tmp_path, capsys):
    artifact_path = tmp_path / "nonstandard-number.json"
    artifact_path.write_text('{"value":NaN}', encoding="utf-8")

    exit_code = main([str(artifact_path)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert json.loads(captured.err)["error"] == "nonstandard_json_constant:NaN"


def test_result_payload_rejects_duplicate_keys_and_nan():
    import hashlib

    for payload in ('{"schema_version":1,"schema_version":1}', '{"value":NaN}'):
        experiment = _experiment()
        record = experiment["execution_record"]
        record["stdout"] = payload
        record["stdout_sha256"] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        result = verify_lab_artifact(experiment)
        assert result["integrity_verified"] is False
        assert result["checks"]["result_payload_digest_matches"] is False

def test_offline_verifier_detects_tampered_summary_fields():
    experiment = _experiment()
    experiment["synthetic_seed_recovered"] = False
    result = verify_lab_artifact(experiment)

    assert result["integrity_verified"] is False
    assert result["checks"]["summary_matches_result_payload"] is False


def test_offline_verifier_rejects_tampered_safety_assertions():
    experiment = _experiment()
    experiment["uses_real_private_keys"] = True
    result = verify_lab_artifact(experiment)

    assert result["integrity_verified"] is False
    assert result["checks"]["safety_assertions_hold"] is False


def test_offline_verifier_rejects_receipt_mutation_after_signing():
    experiment = _experiment()
    private_key = Ed25519PrivateKey.generate()
    experiment["execution_receipt_envelope"] = sign_receipt(
        experiment["execution_receipt"],
        private_key=private_key,
        key_id="trusted-runner",
    )
    experiment["execution_receipt"]["execution"]["exit_code"] = 99

    result = verify_lab_artifact(
        experiment, {"trusted-runner": _public_bytes(private_key)}
    )

    assert result["integrity_verified"] is False
    assert result["checks"]["receipt_digest_matches"] is False
    assert result["authenticity"] == "SIGNATURE_INVALID_OR_UNTRUSTED"
    assert result["signature_verified_against_trusted_key"] is False


def test_offline_verifier_rejects_unsafe_claim_in_result_payload():
    import hashlib

    experiment = _experiment()
    record = experiment["execution_record"]
    payload = json.loads(record["stdout"])
    payload["uses_real_private_keys"] = True
    record["stdout"] = json.dumps(payload, sort_keys=True)
    record["stdout_sha256"] = hashlib.sha256(
        record["stdout"].encode("utf-8")
    ).hexdigest()

    result = verify_lab_artifact(experiment)

    assert result["integrity_verified"] is False
    assert result["checks"]["safety_assertions_hold"] is False
    assert result["checks"]["result_payload_digest_matches"] is False
