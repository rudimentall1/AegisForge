from orchestrator.master import AutonomousPlanner


def test_verified_security_result_can_flow_to_opportunity_hunter():
    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    task = {
        "role": "security_checker",
        "result": {
            "repositories": [{"name": "acme/project"}],
            "security_findings": [{"rule": "example", "severity": "LOW"}],
            "opportunities": [{"target": "acme/project", "thesis": "build tooling"}],
        },
    }
    decision = planner._choose_next_raw(task)
    assert decision[1] == "opportunity_hunter"


def test_opportunity_hunter_output_can_close_after_final_analysis():
    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    task = {
        "role": "analyst",
        "result": {
            "repositories": [{"name": "acme/project"}],
            "opportunities": [{"target": "acme/project", "thesis": "build tooling"}],
            "evaluated_by": "opportunity_hunter",
        },
    }
    decision = planner._choose_next_raw(task)
    assert decision[0] == "COMPLETE"
