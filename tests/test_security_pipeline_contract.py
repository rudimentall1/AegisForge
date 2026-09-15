from orchestrator.master import AutonomousPlanner


def test_security_findings_from_analyst_route_to_developer():
    planner = AutonomousPlanner()

    result = {
        "agent": "analyst",
        "repositories": [
            {
                "name": "owner/repo",
                "url": "https://github.com/owner/repo",
            }
        ],
        "findings": [
            {
                "severity": "HIGH",
                "finding": "authorization risk",
            }
        ],
    }

    task = {
        "id": "test-task",
        "role": "analyst",
        "result": result,
        "parent_task_id": None,
    }

    decision = planner._choose_next_raw(task)

    assert decision[0] == "REFINE"
    assert decision[1] == "developer"


def test_developer_with_technical_review_routes_to_security_checker():
    planner = AutonomousPlanner()

    result = {
        "agent": "developer",
        "technical_review": [
            {
                "name": "owner/repo",
                "smart_contract_project": True,
            }
        ],
        "findings": [
            {
                "severity": "HIGH",
                "finding": "authorization risk",
            }
        ],
    }

    task = {
        "id": "test-task",
        "role": "developer",
        "result": result,
        "parent_task_id": None,
    }

    decision = planner._choose_next_raw(task)

    assert decision[0] == "VERIFY"
    assert decision[1] == "security_checker"


def test_security_checker_contract_error_is_not_retryable():
    planner = AutonomousPlanner()

    task = {
        "result": {
            "error_type": "PipelineContractError",
            "error": (
                "Security Checker received no "
                "technical_review from Developer"
            ),
        }
    }

    assert planner.retryable_failure(task) is False


def test_historical_security_checker_contract_runtime_error_is_not_retryable():
    planner = AutonomousPlanner()

    task = {
        "result": {
            "error_type": "RuntimeError",
            "error": (
                "Security Checker received no "
                "technical_review from Developer"
            ),
        }
    }

    assert planner.retryable_failure(task) is False
PYcd /opt/agent-farm

cat > tests/test_security_pipeline_contract.py <<'PY'
from orchestrator.master import AutonomousPlanner


def test_security_findings_from_analyst_route_to_developer():
    planner = AutonomousPlanner()

    result = {
        "agent": "analyst",
        "repositories": [
            {
                "name": "owner/repo",
                "url": "https://github.com/owner/repo",
            }
        ],
        "findings": [
            {
                "severity": "HIGH",
                "finding": "authorization risk",
            }
        ],
    }

    task = {
        "id": "test-task",
        "role": "analyst",
        "result": result,
        "parent_task_id": None,
    }

    decision = planner._choose_next_raw(task)

    assert decision[0] == "REFINE"
    assert decision[1] == "developer"


def test_developer_with_technical_review_routes_to_security_checker():
    planner = AutonomousPlanner()

    result = {
        "agent": "developer",
        "technical_review": [
            {
                "name": "owner/repo",
                "smart_contract_project": True,
            }
        ],
        "findings": [
            {
                "severity": "HIGH",
                "finding": "authorization risk",
            }
        ],
    }

    task = {
        "id": "test-task",
        "role": "developer",
        "result": result,
        "parent_task_id": None,
    }

    decision = planner._choose_next_raw(task)

    assert decision[0] == "VERIFY"
    assert decision[1] == "security_checker"


def test_security_checker_contract_error_is_not_retryable():
    planner = AutonomousPlanner()

    task = {
        "result": {
            "error_type": "PipelineContractError",
            "error": (
                "Security Checker received no "
                "technical_review from Developer"
            ),
        }
    }

    assert planner.retryable_failure(task) is False


def test_historical_security_checker_contract_runtime_error_is_not_retryable():
    planner = AutonomousPlanner()

    task = {
        "result": {
            "error_type": "RuntimeError",
            "error": (
                "Security Checker received no "
                "technical_review from Developer"
            ),
        }
    }

    assert planner.retryable_failure(task) is False
