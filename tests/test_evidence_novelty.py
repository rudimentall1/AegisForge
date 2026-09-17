from orchestrator.master import AutonomousPlanner


def task(result, role="security_checker"):
    return {"id": "current", "role": role, "result": result}


def test_exact_repeated_findings_have_zero_novelty():
    result = {
        "security_findings": [
            {"rule": "block_timestamp", "severity": "LOW", "file": "A.sol"}
        ],
        "repositories": ["org/repo"],
    }
    history = [task(result), task(result, role="developer")]
    novelty = AutonomousPlanner.novelty_against_history(task(result), history)
    assert novelty[0] == 0.0
    assert novelty[1] == 0


def test_new_finding_is_detected_as_novel():
    old = {"security_findings": [{"rule": "timestamp", "severity": "LOW"}]}
    new = {"security_findings": [
        {"rule": "timestamp", "severity": "LOW"},
        {"rule": "unchecked_call", "severity": "HIGH"},
    ]}
    ratio, novel, total = AutonomousPlanner.novelty_against_history(
        task(new), [task(new), task(old, role="developer")]
    )
    assert novel == 1
    assert total == 2
    assert ratio == 0.5


def test_choose_next_stops_exact_repeat():
    result = {"security_findings": [{"rule": "timestamp", "severity": "LOW"}]}
    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    planner._planning_tasks = {
        "ancestor": task(result, role="developer") | {"id": "ancestor"},
        "current": task(result) | {"id": "current", "parent_task_id": "ancestor"},
    }
    decision = planner.choose_next(planner._planning_tasks["current"])
    assert decision[0] == "COMPLETE"


def test_new_status_counts_as_new_evidence():
    old = {"findings": [{"rule": "x", "severity": "LOW"}], "status": "open"}
    new = {"findings": [{"rule": "x", "severity": "LOW"}], "status": "resolved"}
    ratio, novel, total = AutonomousPlanner.novelty_against_history(
        task(new), [task(new), task(old, role="developer")]
    )
    assert novel == 1
    assert total == 2
    assert ratio == 0.5

# end
