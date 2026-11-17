import base64
import hashlib
import json
from copy import deepcopy

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agents.lab_runner.agent import LabRunner
from agents.validator.agent import Validator
from shared.task import Task
from shared.research_case import (
    CaseValidationError,
    ResearchCase,
    research_case_binding,
)


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



def _research_case(case_id="lab-case-001", *, target_commit="a" * 40):
    return ResearchCase(
        case_id=case_id,
        target_repository="example/protocol",
        target_commit=target_commit,
        scope_url="https://example.com/security-scope",
        scope_digest="b" * 64,
        scope_reviewed_on="2026-10-16",
        hypothesis="A state transition may violate an accounting invariant.",
        attacker_capability="An unprivileged caller can invoke the public method.",
        expected_invariant="The recorded balance matches the calculated balance.",
        falsification_criteria="Counter-tests preserve the invariant.",
        execution_mode="local",
        status="ready",
    )


def test_case_bound_lab_receipt_commits_repository_commit_and_scope():
    case = _research_case()
    binding = research_case_binding(case)
    task = Task(
        task_id="case-bound-lab",
        description="Run a synthetic lab under a registered research case",
        payload={"research_case_id": case.case_id, "research_case": case},
    )

    result = LabRunner().run(task).result
    experiment = result["lab_experiments"][0]
    receipt_case = experiment["execution_receipt"]["inputs"]["research_case"]

    assert result["research_case_binding"] == binding
    assert receipt_case == {
        "schema_version": binding["schema_version"],
        "case_id": case.case_id,
        "case_digest": binding["case_digest"],
        "target_repository": case.target_repository,
        "target_commit": case.target_commit,
        "scope_digest": case.scope_digest,
    }


def test_case_bound_lab_fails_closed_without_registered_case_payload():
    task = Task(
        task_id="missing-case-payload",
        description="Case ID must not be enough to run the lab",
        payload={"research_case_id": "lab-case-missing"},
    )

    with pytest.raises(CaseValidationError, match="Task has no research case"):
        LabRunner().run(task)


def test_case_bound_lab_rejects_case_binding_changed_between_stages():
    prior_case = _research_case(case_id="prior-case")
    current_case = _research_case(case_id="current-case")
    task = Task(
        task_id="changed-case-binding",
        description="A downstream stage cannot silently change its case",
        payload={
            "research_case_id": current_case.case_id,
            "research_case": current_case,
        },
        result={"research_case_binding": research_case_binding(prior_case)},
    )

    with pytest.raises(
        CaseValidationError,
        match="research_case_binding_changed_between_stages",
    ):
        LabRunner().run(task)
