from copy import deepcopy

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
