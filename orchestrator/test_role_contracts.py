import pytest

from orchestrator.role_contracts import (
    ExecutionState,
    ResearchOutcome,
    RoleContractError,
    RoleError,
    RoleExecutionResult,
    validate_role_input,
    validate_role_output,
)


def analyst_output():
    return {
        "agent": "analyst",
        "task": "analyze repositories",
        "research_scope": "technology_intelligence",
        "repositories": [{"name": "owner/repo"}],
        "analysis": [{"name": "owner/repo", "priority": "LOW"}],
        "opportunities": [],
        "count": 1,
    }


def lab_output():
    return {
        "research_track": "evm_key_forensics",
        "stage": "lab",
        "lab_experiments": [{"execution_record": {"test_passed": True}}],
        "lab_summary": {
            "experiments_run": 1,
            "historical_implementation_reproduced": False,
            "real_private_keys_used": False,
            "live_addresses_examined": 0,
            "claim_status": "ILLUSTRATIVE_ONLY",
        },
    }


def security_output():
    return {
        "security_reviews": [{"name": "owner/repo", "findings": []}],
        "security_summary": {
            "repositories_received": 1,
            "repositories_checked": 1,
            "inspection_errors": 0,
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "low_findings": 0,
            "total_findings": 0,
        },
        "security_checker_errors": [],
        "checked_by": "security_checker",
        "security_analysis_type": "static_source_pattern_analysis",
    }


def test_analyst_contract_accepts_existing_output_shape():
    validate_role_output("analyst", analyst_output())


def test_analyst_contract_rejects_missing_required_field():
    output = analyst_output()
    del output["research_scope"]
    with pytest.raises(RoleContractError, match="missing fields"):
        validate_role_output("analyst", output)


def test_analyst_contract_rejects_malformed_nonempty_count():
    output = analyst_output()
    output["count"] = "1"
    with pytest.raises(RoleContractError, match="non-negative integer"):
        validate_role_output("analyst", output)


def test_analyst_input_rejects_non_dictionary_repository():
    with pytest.raises(RoleContractError, match="dictionaries only"):
        validate_role_input("analyst", {"repositories": ["owner/repo"]})


def test_security_checker_requires_technical_review():
    with pytest.raises(RoleContractError, match="received no technical_review"):
        validate_role_input("security_checker", {})


def test_security_checker_rejects_malformed_nonempty_review():
    with pytest.raises(RoleContractError, match="dictionaries only"):
        validate_role_input("security_checker", {"technical_review": ["not-a-review"]})


def test_security_checker_output_rejects_inconsistent_finding_total():
    output = security_output()
    output["security_summary"]["total_findings"] = 1
    with pytest.raises(RoleContractError, match="equal severity counters"):
        validate_role_output("security_checker", output)


def test_lab_runner_requires_matching_case_binding_pair():
    with pytest.raises(RoleContractError, match="together"):
        validate_role_input(
            "lab_runner",
            {},
            {"research_case_id": "case-1"},
        )


def test_lab_runner_rejects_malformed_nonempty_safety_flag():
    output = lab_output()
    output["lab_summary"]["live_addresses_examined"] = "zero"
    with pytest.raises(RoleContractError, match="non-negative integer"):
        validate_role_output("lab_runner", output)


@pytest.mark.parametrize(
    "state,outcome",
    [
        (ExecutionState.FAILED, ResearchOutcome.CONFIRMED),
        (ExecutionState.TIMED_OUT, ResearchOutcome.CONFIRMED),
        (ExecutionState.INCOMPLETE, ResearchOutcome.CONFIRMED),
        (ExecutionState.FAILED, ResearchOutcome.REJECTED),
        (ExecutionState.TIMED_OUT, ResearchOutcome.REJECTED),
        (ExecutionState.INCOMPLETE, ResearchOutcome.REJECTED),
    ],
)
def test_execution_failure_timeout_or_incomplete_cannot_be_conclusive(state, outcome):
    with pytest.raises(RoleContractError, match="cannot yield"):
        RoleExecutionResult(
            role="analyst",
            execution_state=state,
            payload={},
            errors=(RoleError(code="tool_failure", message="synthetic failure"),),
            evidence_refs=("evidence://synthetic",),
            research_outcome=outcome,
            human_approved=True,
        )


def test_confirmed_requires_evidence_and_human_approval():
    with pytest.raises(RoleContractError, match="human approval"):
        RoleExecutionResult(
            role="security_checker",
            execution_state=ExecutionState.SUCCEEDED,
            payload={},
            evidence_refs=("evidence://synthetic",),
            research_outcome=ResearchOutcome.CONFIRMED,
            human_approved=False,
        )


def test_rejected_requires_counter_evidence_reference():
    with pytest.raises(RoleContractError, match="counter-evidence"):
        RoleExecutionResult(
            role="analyst",
            execution_state=ExecutionState.SUCCEEDED,
            payload={},
            research_outcome=ResearchOutcome.REJECTED,
        )


def test_timeout_can_be_explicitly_inconclusive():
    result = RoleExecutionResult(
        role="lab_runner",
        execution_state=ExecutionState.TIMED_OUT,
        payload={},
        errors=(RoleError(code="timeout", message="synthetic timeout"),),
        research_outcome=ResearchOutcome.INCONCLUSIVE,
    )
    assert result.execution_state is ExecutionState.TIMED_OUT
    assert result.research_outcome is ResearchOutcome.INCONCLUSIVE
