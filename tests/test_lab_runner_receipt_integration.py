import base64
import hashlib
import json
from copy import deepcopy

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agents.lab_runner.agent import LabRunner
from agents.validator.agent import Validator
from shared.task import Task


def _validate(experiment):
    validator = Validator.__new__(Validator)
    validator.source_fetcher = lambda url: {}
    task = Task(
        task_id="lab-receipt-integration",
        description="Validate canonical receipt emitted by the synthetic lab runner",
        result={
            "research_track": "evm_key_forensics",
            "stage": "lab",
            "sources": [],
            "hypotheses": [],
            "lab_experiments": [experiment],
        },
    )
    return validator.run(task).result["research_validation"]


def test_lab_runner_receipt_integrity_is_verified_but_not_trusted():
    experiment = LabRunner.run_synthetic_entropy_demo()
    validation = _validate(experiment)

    assert experiment["execution_receipt"]["receipt_type"] == "aegisforge.lab_execution"
    assert experiment["execution_receipt_sha256"]
    assert validation["lab_execution_receipts_checked"] == 1
    assert validation["lab_execution_receipts_integrity_verified"] is True
    assert validation["lab_execution_receipts_trusted"] is False

    receipt_check = validation["lab_execution_receipt_checks"][0]
    assert receipt_check["integrity_verified"] is True
    assert receipt_check["authenticity"] == "UNTRUSTED_UNSIGNED"


def test_validator_detects_receipt_tampering_and_missing_receipt():
    experiment = LabRunner.run_synthetic_entropy_demo()
    tampered = deepcopy(experiment)
    tampered["execution_receipt"]["execution"]["test_passed"] = False

    validation = _validate(tampered)
    receipt_check = validation["lab_execution_receipt_checks"][0]
    assert receipt_check["digest_matches"] is False
    assert receipt_check["record_matches_receipt"] is False
    assert validation["lab_execution_receipts_integrity_verified"] is False
    assert validation["lab_execution_receipts_trusted"] is False

    missing = deepcopy(experiment)
    missing.pop("execution_receipt")
    missing_validation = _validate(missing)
    missing_check = missing_validation["lab_execution_receipt_checks"][0]
    assert missing_check["receipt_present"] is False
    assert missing_check["integrity_verified"] is False



def test_signed_receipt_is_trusted_only_with_explicit_matching_public_key(monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    monkeypatch.setenv("AEGISFORGE_LAB_SIGNING_KEY_B64", base64.b64encode(private_bytes).decode("ascii"))
    monkeypatch.setenv("AEGISFORGE_LAB_SIGNING_KEY_ID", "test-runner")
    monkeypatch.setenv(
        "AEGISFORGE_LAB_TRUSTED_PUBLIC_KEYS",
        json.dumps({"test-runner": base64.b64encode(public_bytes).decode("ascii")}),
    )

    experiment = LabRunner.run_synthetic_entropy_demo()
    assert experiment["execution_receipt_signed"] is True
    validation = _validate(experiment)
    receipt_check = validation["lab_execution_receipt_checks"][0]
    assert receipt_check["signature_verified_against_trusted_key"] is True
    assert receipt_check["authenticity"] == "SIGNED_AND_TRUSTED"
    assert validation["lab_execution_receipts_trusted"] is True


def test_signed_receipt_is_not_trusted_when_key_is_not_configured(monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    monkeypatch.setenv("AEGISFORGE_LAB_SIGNING_KEY_B64", base64.b64encode(private_bytes).decode("ascii"))
    monkeypatch.setenv("AEGISFORGE_LAB_SIGNING_KEY_ID", "runner-not-trusted")
    monkeypatch.setenv("AEGISFORGE_LAB_TRUSTED_PUBLIC_KEYS", json.dumps({}))

    experiment = LabRunner.run_synthetic_entropy_demo()
    validation = _validate(experiment)
    receipt_check = validation["lab_execution_receipt_checks"][0]
    assert receipt_check["signature_present"] is True
    assert receipt_check["signature_verified_against_trusted_key"] is False
    assert receipt_check["authenticity"] == "SIGNATURE_INVALID_OR_UNTRUSTED"
    assert validation["lab_execution_receipts_trusted"] is False



def test_signed_envelope_must_bind_to_the_exact_receipt_being_validated(monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    monkeypatch.setenv("AEGISFORGE_LAB_SIGNING_KEY_B64", base64.b64encode(private_bytes).decode("ascii"))
    monkeypatch.setenv("AEGISFORGE_LAB_SIGNING_KEY_ID", "bound-runner")
    monkeypatch.setenv(
        "AEGISFORGE_LAB_TRUSTED_PUBLIC_KEYS",
        json.dumps({"bound-runner": base64.b64encode(public_bytes).decode("ascii")}),
    )

    experiment = LabRunner.run_synthetic_entropy_demo()
    # Mutate the plain receipt but leave the signed envelope untouched. The
    # validator must not treat the valid signature over the old receipt as trust
    # for the now-different receipt in the dossier.
    experiment["execution_receipt"]["execution"]["test_passed"] = False
    validation = _validate(experiment)
    receipt_check = validation["lab_execution_receipt_checks"][0]
    assert receipt_check["signature_verified_against_trusted_key"] is False
    assert receipt_check["authenticity"] == "SIGNATURE_INVALID_OR_UNTRUSTED"
    assert validation["lab_execution_receipts_trusted"] is False



def test_receipt_binds_the_observed_command_and_result_payload():
    experiment = LabRunner.run_synthetic_entropy_demo()
    # JSON round-trip models the portable artifact: object aliasing from the
    # in-memory runner result must not survive serialization as shared references.
    changed_command = json.loads(json.dumps(experiment))
    changed_command["execution_record"]["command"][-1] = "print('different command')"
    changed_command["execution_record"]["command_sha256"] = hashlib.sha256(
        json.dumps(
            changed_command["execution_record"]["command"],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    command_validation = _validate(changed_command)
    command_check = command_validation["lab_execution_record_checks"][0]
    receipt_check = command_validation["lab_execution_receipt_checks"][0]
    # The record is internally self-consistent after recalculating its own hash,
    # but it no longer matches the command committed into the receipt.
    assert command_check["internally_consistent"] is True
    assert receipt_check["command_matches_receipt"] is False
    assert receipt_check["integrity_verified"] is False

    changed_artifact = deepcopy(experiment)
    changed_artifact["execution_receipt"]["artifacts"]["result_payload_sha256"] = "0" * 64
    # Recalculate the public digest to isolate artifact binding from digest checks.
    from shared.lab_execution_receipt import receipt_sha256
    changed_artifact["execution_receipt_sha256"] = receipt_sha256(
        changed_artifact["execution_receipt"]
    )
    artifact_validation = _validate(changed_artifact)
    artifact_check = artifact_validation["lab_execution_receipt_checks"][0]
    assert artifact_check["result_payload_digest_matches"] is False
    assert artifact_check["integrity_verified"] is False
