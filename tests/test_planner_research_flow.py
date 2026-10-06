from orchestrator.master import AutonomousPlanner


def test_analyst_research_results_continue_into_technical_investigation():
    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    task = {
        "role": "analyst",
        "result": {
            "repositories": [
                {"name": "acme/project", "url": "https://github.com/acme/project"}
            ],
            "analysis": [{"name": "acme/project", "priority": "HIGH", "stars": 1200}],
        },
    }
    decision = planner._choose_next_raw(task)
    assert decision[0] == "REFINE"
    assert decision[1] == "developer"


def test_analysis_is_distinct_evidence_from_repository_discovery():
    research = {
        "repositories": [{"name": "acme/project", "url": "https://github.com/acme/project"}]
    }
    analysis = {
        **research,
        "analysis": [{"name": "acme/project", "priority": "HIGH", "stars": 1200}],
    }
    assert AutonomousPlanner.evidence_atoms(analysis) - AutonomousPlanner.evidence_atoms(research)


def test_developer_repository_batch_is_bounded():
    from agents.developer.agent import Developer
    assert Developer.MAX_REPOSITORIES_PER_RUN == 4


def test_developer_core_api_fallback_uses_canonical_files(monkeypatch):
    from agents.developer.agent import Developer

    developer = Developer.__new__(Developer)
    developer.github = type("GH", (), {"BASE_URL": "https://api.github.com"})()

    def exhausted(*args, **kwargs):
        raise RuntimeError("GitHub API core cooldown active")

    monkeypatch.setattr(developer, "_get", exhausted)
    tree = developer._get_tree("owner", "repo", "main")

    paths = {entry["path"] for entry in tree["tree"]}
    assert tree["fallback"] is True
    assert "README.md" in paths
    assert "package.json" in paths
    assert ".github/workflows/ci.yml" in paths


def test_planner_applies_live_queue_backpressure(tmp_path, monkeypatch):
    import shared.queue as queue_module
    from orchestrator.master import MAX_LIVE_TASKS, AutonomousPlanner

    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "queue.db")
    q = queue_module.TaskQueue()
    for i in range(MAX_LIVE_TASKS):
        q.add(f"live-{i}", role="validator")
    completed = q.add("completed", role="analyst")
    q.db.execute(
        "UPDATE queue SET status='completed', result='{}', finished_at=datetime('now') WHERE id=?",
        (completed,),
    )
    q.db.commit()

    planner = AutonomousPlanner(q)
    result = planner.plan()

    assert result["state"] == "BACKPRESSURE"
    assert result["created"] == 0
    assert q.db.execute("SELECT COUNT(*) FROM queue WHERE status='pending'").fetchone()[0] == MAX_LIVE_TASKS
    q.db.close()


def test_commercial_shortcut_requires_technical_review():
    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    task = {
        "role": "analyst",
        "result": {
            "repositories": [{"name": "acme/project", "url": "https://github.com/acme/project"}],
            "opportunities": [{"target": "acme/project", "product_thesis": "test"}],
        },
    }
    primary = planner._choose_next_raw(task)
    candidates = planner.candidate_decisions(task, primary)
    assert primary[1] == "developer"
    assert [candidate[1] for candidate in candidates] == ["developer"]


def test_commercial_shortcut_allowed_after_technical_review():
    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    task = {
        "role": "analyst",
        "result": {
            "repositories": [{"name": "acme/project", "url": "https://github.com/acme/project"}],
            "opportunities": [{"target": "acme/project", "product_thesis": "test"}],
            "technical_review": [{"name": "acme/project", "technical_maturity_score": 8}],
        },
    }
    primary = planner._choose_next_raw(task)
    candidates = planner.candidate_decisions(task, primary)
    assert primary[1] == "developer"
    assert {candidate[1] for candidate in candidates} == {"developer", "opportunity_hunter"}


def test_opportunity_hunter_exposes_learning_branch_before_validation():
    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    task = {
        "role": "opportunity_hunter",
        "result": {
            "opportunities": [
                {
                    "target": "acme/project",
                    "product_thesis": "test",
                    "problem_signal": "specific pain",
                    "validation_experiment": "commercial probe",
                }
            ]
        },
    }
    primary = planner._choose_next_raw(task)
    candidates = planner.candidate_decisions(task, primary)
    assert primary[1] == "validator"
    assert {candidate[1] for candidate in candidates} == {"validator", "analyst"}


def test_opportunity_hunter_escapes_stagnating_analyst_path():
    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    planner.contextual_action_history = lambda task, action_role, history=None: (
        {"uses": 2, "recent_ratio": 0.40, "samples": 2}
        if action_role == "analyst"
        else {"uses": 0, "recent_ratio": 1.0, "samples": 0}
    )
    task = {
        "role": "opportunity_hunter",
        "result": {
            "opportunities": [
                {
                    "target": "acme/project",
                    "product_thesis": "test",
                    "problem_signal": "specific pain",
                    "validation_experiment": "commercial probe",
                },
                {
                    "target": "acme/project",
                    "product_thesis": "test",
                    "problem_signal": "specific pain",
                    "validation_experiment": "commercial probe",
                }
            ]
        },
    }
    primary = planner._choose_next_raw(task)
    candidates = planner.candidate_decisions(task, primary)
    assert {candidate[1] for candidate in candidates} == {"analyst", "researcher"}


def test_contextual_action_history_detects_diminishing_returns():
    import sqlite3

    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE planner_action_outcomes (action_role TEXT, parent_task_id TEXT, expected_evidence_gain REAL, actual_evidence_gain REAL, observed_at TEXT)")
    db.executemany("INSERT INTO planner_action_outcomes VALUES (?, ?, ?, ?, ?)", [
        ("analyst", "p1", 0.1282, 0.0, "2"),
        ("analyst", "p2", 0.1282, 0.0, "1"),
    ])
    planner.queue = type("Queue", (), {"db": db})()

    result = planner.contextual_action_history(
        {"id": "current"},
        "analyst",
        history=[{"id": "p1"}, {"id": "p2"}],
    )

    assert result["samples"] == 2
    assert result["recent_ratio"] == 0.0



def test_contextual_action_history_falls_back_to_same_parent_role(tmp_path, monkeypatch):
    import shared.queue as queue_module

    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "queue.db")
    queue = queue_module.TaskQueue()
    planner = AutonomousPlanner(queue)

    current = queue.add("current opportunity hunt", role="opportunity_hunter")
    prior_one = queue.add("prior opportunity hunt 1", role="opportunity_hunter")
    prior_two = queue.add("prior opportunity hunt 2", role="opportunity_hunter")
    queue.db.executemany(
        """
        INSERT INTO planner_action_outcomes
        (child_task_id, parent_task_id, action_role, expected_evidence_gain,
         action_cost, action_efficiency, actual_evidence_gain, novelty,
         novel_atom_count, atom_count, prediction_error, observed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            ("child-1", prior_one, "analyst", 0.20, 0.35, 0.57, 0.02, 0.10, 1, 10, -0.18, "2"),
            ("child-2", prior_two, "analyst", 0.20, 0.35, 0.57, 0.04, 0.20, 2, 10, -0.16, "1"),
        ],
    )
    queue.db.commit()

    result = planner.contextual_action_history(
        {"id": current, "role": "opportunity_hunter"},
        "analyst",
        history=[{"id": current, "role": "opportunity_hunter"}],
    )

    assert result["samples"] == 2
    assert result["recent_ratio"] == 0.15
    queue.db.close()
