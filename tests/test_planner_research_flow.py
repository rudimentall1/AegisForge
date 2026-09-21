from orchestrator.master import AutonomousPlanner


def test_analyst_research_results_continue_into_technical_investigation():
    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    task = {
        "role": "analyst",
        "result": {
            "repositories": [
                {"name": "acme/project", "url": "https://github.com/acme/project"}
            ],
            "analysis": [{"name": "acme/project", "priority": "HIGH"}],
        },
    }
    decision = planner._choose_next_raw(task)
    assert decision[0] == "REFINE"
    assert decision[1] == "developer"
