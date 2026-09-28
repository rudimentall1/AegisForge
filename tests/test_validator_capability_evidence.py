import sqlite3

from shared.capability_policy import CapabilityDecision
from shared.evidence_ledger import EvidenceLedger
from shared.task import Task
from agents.validator.agent import Validator


def capability_parent_result(evidence_claims=None):
    result = {
        "error_type": "CapabilityEvidenceRequired",
        "decision": CapabilityDecision.REQUIRE_EVIDENCE.value,
        "intent": {
            "role": "developer",
            "action": "deploy",
            "target": "",
            "resource": "application",
            "destination": "staging",
            "data_scope": "source_code",
            "irreversible": True,
            "requires_network": False,
            "requires_shell": False,
            "requires_filesystem": True,
            "financial": False,
            "privileged": False,
            "read_only": False,
            "evidence_required": False,
        },
    }
    if evidence_claims is not None:
        result["evidence_claims"] = evidence_claims
    return result


def test_validator_requires_real_evidence_claims_without_execution():
    task = Task(
        task_id="validator-1",
        description="[CAPABILITY_EVIDENCE_REQUEST] verify authorization prerequisites",
        payload={
            "parent_task_id": "parent-1",
            "parent_result": capability_parent_result(),
            "capability_intent": {
                "action": "verify",
                "resource": "authorization_prerequisites",
                "destination": "internal",
                "data_scope": "validation_evidence",
                "read_only": True,
            },
        },
        result=None,
        status="running",
    )

    result = Validator().run(task)

    assert result.status == "validated"
    assert result.result["validation_mode"] == "capability_evidence"
    assert result.result["status"] == "INSUFFICIENT_EVIDENCE"
    assert result.result["checks"]["required_evidence"] == [
        "rollback_or_recovery_ready",
        "rollback_ready",
        "security_scan_passed",
        "tests_passed",
    ]
    assert result.result["checks"]["missing_evidence"] == [
        "rollback_or_recovery_ready",
        "rollback_ready",
        "security_scan_passed",
        "tests_passed",
    ]
    assert result.result["execution_performed"] is False
    assert result.result["parent_task_id"] == "parent-1"


def test_validator_verifies_capability_request_with_structured_evidence_claims():
    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    recorded = {
        "tests_passed": ledger.record_capability_claim(
            "evidence-tests",
            "developer",
            "tests_passed",
        ),
        "security_scan_passed": ledger.record_capability_claim(
            "evidence-security",
            "security_checker",
            "security_scan_passed",
            status="VERIFIED",
        ),
        "rollback_or_recovery_ready": ledger.record_capability_claim(
            "evidence-recovery",
            "developer",
            "rollback_or_recovery_ready",
        ),
        "rollback_ready": ledger.record_capability_claim(
            "evidence-rollback",
            "developer",
            "rollback_ready",
        ),
    }
    claims = {
        key: {
            "status": value["status"],
            "source": value["source"],
            "evidence_id": value["evidence_id"],
        }
        for key, value in recorded.items()
    }
    task = Task(
        task_id="validator-1c",
        description="[CAPABILITY_EVIDENCE_REQUEST] verify authorization prerequisites",
        payload={
            "parent_task_id": "parent-1c",
            "parent_result": capability_parent_result(claims),
            "capability_intent": {
                "action": "verify",
                "resource": "authorization_prerequisites",
                "destination": "internal",
                "data_scope": "validation_evidence",
                "read_only": True,
            },
        },
        result=None,
        status="running",
    )

    validator = Validator(evidence_ledger=ledger)
    result = validator.run(task)

    assert result.status == "validated"
    assert result.result["status"] == "VERIFIED"
    assert result.result["checks"]["missing_evidence"] == []
    assert result.result["execution_performed"] is False


def test_validator_verifies_capability_request_when_intent_is_json_string():
    task = Task(
        task_id="validator-1b",
        description="[CAPABILITY_EVIDENCE_REQUEST] verify authorization prerequisites",
        payload={
            "parent_task_id": "parent-1b",
            "parent_result": capability_parent_result(),
            "capability_intent": '{"action":"verify","resource":"authorization_prerequisites"}',
        },
        result=None,
        status="running",
    )

    result = Validator().run(task)

    assert result.status == "validated"
    assert result.result["status"] == "INSUFFICIENT_EVIDENCE"


def test_validator_does_not_verify_non_capability_task_without_opportunities():
    task = Task(
        task_id="validator-2",
        description="normal validation",
        payload={},
        result={},
        status="running",
    )

    result = Validator().run(task)

    assert result.status == "validation_failed"
    assert result.result["error_type"] == "NoOpportunities"


def test_validator_rejects_fabricated_evidence_ids():
    claims = {
        "tests_passed": {
            "status": "PASS",
            "source": "developer",
            "evidence_id": "not-in-ledger",
        },
        "security_scan_passed": {
            "status": "VERIFIED",
            "source": "security_checker",
            "evidence_id": "not-in-ledger-2",
        },
        "rollback_or_recovery_ready": {
            "status": "PASS",
            "source": "developer",
            "evidence_id": "not-in-ledger-3",
        },
        "rollback_ready": {
            "status": "PASS",
            "source": "developer",
            "evidence_id": "not-in-ledger-4",
        },
    }
    task = Task(
        task_id="validator-forged",
        description="[CAPABILITY_EVIDENCE_REQUEST] verify authorization prerequisites",
        payload={
            "parent_task_id": "parent-forged",
            "parent_result": capability_parent_result(claims),
            "capability_intent": {
                "action": "verify",
                "resource": "authorization_prerequisites",
            },
        },
        result=None,
        status="running",
    )

    result = Validator(evidence_ledger=EvidenceLedger(sqlite3.connect(":memory:"))).run(task)

    assert result.result["status"] == "INSUFFICIENT_EVIDENCE"
    assert all(
        value is False
        for value in result.result["checks"]["evidence_ledger_bound"].values()
    )


def test_validator_rejects_evidence_from_unauthorized_source_role():
    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    recorded = ledger.record_capability_claim(
        "evidence-tests-source",
        "developer",
        "tests_passed",
    )
    claims = {
        "tests_passed": {
            "status": "PASS",
            "source": "security_checker",
            "evidence_id": recorded["evidence_id"],
        },
        "security_scan_passed": {
            "status": "VERIFIED",
            "source": "security_checker",
            "evidence_id": "fake-security",
        },
        "rollback_or_recovery_ready": {
            "status": "PASS",
            "source": "developer",
            "evidence_id": "fake-recovery",
        },
        "rollback_ready": {
            "status": "PASS",
            "source": "developer",
            "evidence_id": "fake-rollback",
        },
    }
    task = Task(
        task_id="validator-wrong-source",
        description="[CAPABILITY_EVIDENCE_REQUEST] verify authorization prerequisites",
        payload={
            "parent_task_id": "parent-wrong-source",
            "parent_result": capability_parent_result(claims),
            "capability_intent": {
                "action": "verify",
                "resource": "authorization_prerequisites",
            },
        },
        result=None,
        status="running",
    )

    result = Validator(evidence_ledger=ledger).run(task)

    assert result.result["status"] == "INSUFFICIENT_EVIDENCE"
    assert result.result["checks"]["evidence_ledger_bound"]["tests_passed"] is False
