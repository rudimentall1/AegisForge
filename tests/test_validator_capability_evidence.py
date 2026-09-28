from shared.capability_policy import CapabilityDecision
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
    claims = {
        "tests_passed": {
            "status": "PASS",
            "source": "test_suite",
            "evidence_id": "tests-123",
        },
        "security_scan_passed": {
            "status": "VERIFIED",
            "source": "security_checker",
            "evidence_id": "scan-456",
        },
        "rollback_or_recovery_ready": {
            "status": "PASS",
            "source": "deployment_preflight",
            "evidence_id": "rollback-789",
        },
        "rollback_ready": {
            "status": "PASS",
            "source": "deployment_preflight",
            "evidence_id": "rollback-790",
        },
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

    result = Validator().run(task)

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
