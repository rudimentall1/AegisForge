from shared.capability_policy import CapabilityDecision
from shared.task import Task
from agents.validator.agent import Validator


def capability_parent_result():
    return {
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


def test_validator_verifies_structured_capability_evidence_without_execution():
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
    assert result.result["status"] == "VERIFIED"
    assert result.result["execution_performed"] is False
    assert result.result["parent_task_id"] == "parent-1"


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
    assert result.result["status"] == "VERIFIED"


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
