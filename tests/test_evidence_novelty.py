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


def test_evidence_quality_policy_routes_unconfirmed_security_evidence():
    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    result = {
        "security_findings": [{"rule": "r1", "severity": "LOW"}],
        "repositories": ["org/repo"],
    }
    decision = planner._evidence_quality_policy(
        task(result, role="analyst"),
        {"unconfirmed": 1, "corroborated": 0, "multi_source": 0, "contested": 0},
    )
    assert decision[0:2] == ("REFINE", "developer")


def test_evidence_quality_policy_requires_independent_verification_for_contested():
    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    result = {"security_findings": [{"rule": "r1", "status": "POTENTIAL_RISK"}], "technical_review": {"ok": True}}
    decision = planner._evidence_quality_policy(
        task(result, role="developer"),
        {"unconfirmed": 0, "corroborated": 0, "multi_source": 0, "contested": 1},
    )
    assert decision[0:2] == ("VERIFY", "security_checker")


def test_evidence_quality_policy_allows_corroborated_and_multi_source():
    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    result = {"security_findings": [{"rule": "r1", "severity": "LOW"}]}
    for quality in (
        {"unconfirmed": 0, "corroborated": 1, "multi_source": 0, "contested": 0},
        {"unconfirmed": 0, "corroborated": 0, "multi_source": 1, "contested": 0},
    ):
        assert planner._evidence_quality_policy(task(result), quality) is None


def test_incomplete_developer_coverage_is_not_advanced():
    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    result = {
        "security_findings": [{"rule": "r1", "severity": "HIGH"}],
        "developer_integrity": {
            "expected_repositories": 3,
            "inspected_repositories": 2,
            "inspection_errors": 1,
            "complete": False,
        },
    }
    decision = planner.choose_next(
        task(result, role="developer") | {"id": "current"}
    )
    assert decision[0] == "COMPLETE"
    assert "2/3" in decision[3]


def test_complete_coverage_does_not_block_planner():
    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    result = {
        "security_findings": [{"rule": "r1", "severity": "HIGH"}],
        "developer_summary": {
            "repositories_received": 2,
            "repositories_inspected": 2,
            "inspection_errors": 0,
        },
        "technical_review": [{"name": "repo/a"}, {"name": "repo/b"}],
    }
    coverage = planner.coverage_summary(result)
    assert coverage["complete"] is True
    assert planner._coverage_policy(
        task(result, role="developer"), coverage
    ) is None


def test_contested_developer_is_forced_to_independent_verification():
    import sqlite3
    from shared.evidence_ledger import EvidenceLedger

    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    risky = {"finding:" + __import__("json").dumps({
        "repository": "repo-a", "file": "x.py", "rule": "r1",
        "description": "issue", "status": "POTENTIAL_RISK"
    }, sort_keys=True, separators=(",", ":"))}
    safe = {"finding:" + __import__("json").dumps({
        "repository": "repo-a", "file": "x.py", "rule": "r1",
        "description": "issue", "status": "SAFE"
    }, sort_keys=True, separators=(",", ":"))}
    ledger.record("task-1", "security_checker", risky)
    ledger.record("task-2", "analyst", safe)

    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    planner.evidence_ledger = ledger
    current = task({
        "findings": [__import__("json").loads(next(iter(safe))[len("finding:"):])],
        "technical_review": {"validated": True},
    }, role="developer") | {"id": "current", "parent_task_id": "ancestor"}
    ancestor = task({
        "findings": [__import__("json").loads(next(iter(risky))[len("finding:"):])],
    }, role="security_checker") | {"id": "ancestor"}
    planner._planning_tasks = {"ancestor": ancestor, "current": current}

    decision = planner.choose_next(current)
    assert decision[0] == "VERIFY"
    assert decision[1] == "security_checker"


def test_action_cost_is_bounded_and_role_sensitive():
    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    assert planner.action_cost("researcher") < planner.action_cost("security_checker")
    assert 0.0 < planner.action_cost("researcher") <= 1.0
    assert 0.0 < planner.action_cost("security_checker") <= 1.0


def test_action_economics_exposes_expected_gain_per_cost():
    from shared.evidence_ledger import EvidenceLedger
    import sqlite3
    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    planner.evidence_ledger = EvidenceLedger(sqlite3.connect(":memory:"))
    planner._planning_tasks = {}
    result = {
        "repositories": ["org/repo"],
        "security_findings": [{"rule": "r1", "severity": "HIGH"}],
    }
    decision = (
        "REFINE",
        "developer",
        "inspect target",
        "technical evidence is needed",
        0.70,
    )
    economics = planner.action_economics(
        task(result, role="analyst") | {"id": "current"},
        decision,
    )
    assert economics["action"] == "developer"
    assert economics["cost"] == 0.65
    assert economics["expected_evidence_gain"] > 0.0
    assert economics["efficiency"] > 0.0


def test_choose_next_records_action_economics_in_reason():
    from shared.evidence_ledger import EvidenceLedger
    import sqlite3
    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    planner.evidence_ledger = EvidenceLedger(sqlite3.connect(":memory:"))
    planner._planning_tasks = {}
    result = {"repositories": ["org/repo"], "status": "research_completed"}
    decision = planner.choose_next(
        task(result, role="researcher") | {"id": "current"}
    )
    assert decision[0] == "CONTINUE"
    assert "Action economics:" in decision[3]
    assert "expected_evidence_gain=" in decision[3]


def test_select_action_prefers_higher_evidence_per_cost():
    from shared.evidence_ledger import EvidenceLedger
    import sqlite3
    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    planner.evidence_ledger = EvidenceLedger(sqlite3.connect(":memory:"))
    planner._planning_tasks = {}
    current = task(
        {"repositories": ["org/repo"], "status": "research_completed"},
        role="researcher",
    ) | {"id": "current"}

    primary = (
        "ESCALATE",
        "model_researcher",
        "expensive path",
        "candidate",
        0.60,
    )
    selected, options = planner.select_action(current, primary)

    assert selected[1] == "analyst"
    assert len(options) >= 2
    assert options[0]["efficiency"] >= options[1]["efficiency"]
