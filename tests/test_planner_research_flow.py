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
