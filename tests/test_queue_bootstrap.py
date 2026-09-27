import shared.queue as queue_module
from shared.queue import TaskQueue


def test_has_tasks_ignores_completed_and_failed_history(tmp_path, monkeypatch):
    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "queue.db")
    q = TaskQueue()
    first = q.add("old completed", "researcher")
    q.db.execute("UPDATE queue SET status='completed' WHERE id=?", (first,))
    second = q.add("old failed", "researcher")
    q.db.execute("UPDATE queue SET status='failed' WHERE id=?", (second,))
    q.db.commit()
    assert q.has_tasks() is False
    q.db.close()


def test_has_tasks_detects_live_work(tmp_path, monkeypatch):
    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "queue.db")
    q = TaskQueue()
    q.add("live task", "researcher")
    assert q.has_tasks() is True
    q.db.close()

def test_repair_active_orphans_removes_pending_subtree(tmp_path, monkeypatch):
    import shared.queue as queue_module
    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "queue.db")
    q = queue_module.TaskQueue()
    root = q.add("missing-parent-child", role="researcher", parent_task_id="missing")
    child = q.add("grandchild", role="analyst", parent_task_id=root)
    assert q.repair_active_orphans() == 2
    assert q.get(root) is None
    assert q.get(child) is None


def test_has_planner_work_detects_completed_unplanned_task(tmp_path, monkeypatch):
    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "queue.db")
    q = TaskQueue()
    task_id = q.add("completed but not planned", "researcher")
    q.db.execute(
        "UPDATE queue SET status='completed', result=? WHERE id=?",
        ('{"repositories":[{"name":"example/repo"}]}', task_id),
    )
    q.db.commit()
    assert q.has_tasks() is False
    assert q.has_planner_work() is True
    q.mark_planner_decision(task_id, "COMPLETE", 0.0, "test-fingerprint")
    assert q.has_planner_work() is False
    q.db.close()


def test_action_outcome_records_bounded_calibration_feedback(tmp_path, monkeypatch):
    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "queue.db")
    q = TaskQueue()
    parent = q.add("parent", "researcher")
    child = q.add("child", "analyst", parent_task_id=parent)
    q.db.execute("UPDATE queue SET status='completed' WHERE id=?", (child,))
    q.db.commit()
    q.mark_planner_decision(parent, "CONTINUE", 0.6, "fp", "analyst", 0.7, 0.35, 2.0)
    assert q.record_action_outcome(child, 0.5, 0.8, 4, 5) is True
    assert q.record_action_outcome(child, 0.5, 0.8, 4, 5) is False
    row = q.db.execute("SELECT expected_evidence_gain, actual_evidence_gain, prediction_error FROM planner_action_outcomes").fetchone()
    assert row == (0.7, 0.5, -0.19999999999999996)
    summary = q.action_outcome_summary()
    assert summary["metric_version"] == 2
    assert summary["samples"] == 1
    assert summary["by_role"]["analyst"]["samples"] == 1
    q.db.close()


def _insert_planner_outcome(q, idx, role, expected, actual):
    q.db.execute(
        """
        INSERT INTO planner_action_outcomes
        (child_task_id, parent_task_id, action_role, expected_evidence_gain,
         action_cost, action_efficiency, actual_evidence_gain, novelty,
         novel_atom_count, atom_count, prediction_error, observed_at, metric_version)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 2)
        """,
        (
            f"child-{idx}", f"parent-{idx}", role, expected, 0.35,
            expected / 0.35 if expected else 0.0, actual, actual,
            1, 1, actual - expected, f"2026-09-27T00:00:{idx:02d}+00:00",
        ),
    )
    q.db.commit()


def test_action_calibration_neutral_without_enough_history(tmp_path, monkeypatch):
    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "queue.db")
    q = TaskQueue()
    assert q.action_calibration("analyst")["factor"] == 1.0
    _insert_planner_outcome(q, 1, "analyst", 0.8, 0.2)
    _insert_planner_outcome(q, 2, "analyst", 0.8, 0.2)
    calibration = q.action_calibration("analyst")
    assert calibration["samples"] == 2
    assert calibration["factor"] == 1.0
    q.db.close()


def test_action_calibration_shrinks_biased_history(tmp_path, monkeypatch):
    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "queue.db")
    q = TaskQueue()
    for idx in range(1, 6):
        _insert_planner_outcome(q, idx, "developer", 0.8, 0.4)
    calibration = q.action_calibration("developer")
    assert calibration["samples"] == 5
    assert 0.75 < calibration["factor"] < 1.0
    assert calibration["weight"] == 0.375
    q.db.close()


def test_action_calibration_never_exceeds_bounded_adjustment(tmp_path, monkeypatch):
    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "queue.db")
    q = TaskQueue()
    for idx in range(1, 11):
        _insert_planner_outcome(q, idx, "security_checker", 0.8, 1.0)
    calibration = q.action_calibration("security_checker")
    assert calibration["factor"] == 1.25
    q.db.close()


def test_planner_applies_calibration_and_accepts_persisted_dict(tmp_path, monkeypatch):
    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "queue.db")
    from orchestrator.master import AutonomousPlanner

    q = TaskQueue()
    for idx in range(1, 11):
        _insert_planner_outcome(q, idx, "analyst", 0.8, 0.4)

    planner = AutonomousPlanner(q)
    monkeypatch.setattr(
        planner,
        "expected_evidence_gain",
        lambda task, decision: 0.8,
    )
    task = {"role": "researcher", "result": {}}
    decision = {
        "decision": "CONTINUE",
        "role": "analyst",
        "description": "test",
        "reason": "test",
        "information_gain": 0.5,
    }
    economics = planner.action_economics(task, decision)
    assert economics["action"] == "analyst"
    assert economics["expected_evidence_gain"] == 0.6
    assert economics["calibration"]["factor"] == 0.75
    q.db.close()


def test_action_calibration_prefers_source_to_action_signature(tmp_path, monkeypatch):
    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "queue.db")
    q = TaskQueue()
    analyst_parent = q.add("analyst parent", "analyst")
    researcher_parent = q.add("researcher parent", "researcher")
    for idx in range(1, 4):
        q.db.execute(
            """
            INSERT INTO planner_action_outcomes
            (child_task_id, parent_task_id, action_role, expected_evidence_gain,
             action_cost, action_efficiency, actual_evidence_gain, novelty,
             novel_atom_count, atom_count, prediction_error, observed_at, metric_version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 2)
            """,
            (f"sig-child-a-{idx}", analyst_parent, "developer", 0.8, 0.65, 1.0,
             0.4, 0.4, 1, 1, -0.4, f"2026-09-27T03:00:{idx:02d}+00:00"),
        )
        q.db.execute(
            """
            INSERT INTO planner_action_outcomes
            (child_task_id, parent_task_id, action_role, expected_evidence_gain,
             action_cost, action_efficiency, actual_evidence_gain, novelty,
             novel_atom_count, atom_count, prediction_error, observed_at, metric_version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 2)
            """,
            (f"sig-child-r-{idx}", researcher_parent, "developer", 0.8, 0.65, 1.0,
             0.8, 0.8, 1, 1, 0.0, f"2026-09-27T03:01:{idx:02d}+00:00"),
        )
    q.db.commit()
    analyst_cal = q.action_calibration("developer", source_role="analyst")
    researcher_cal = q.action_calibration("developer", source_role="researcher")
    assert analyst_cal["scope"] == "signature"
    assert analyst_cal["signature_samples"] == 3
    assert researcher_cal["scope"] == "signature"
    assert researcher_cal["signature_samples"] == 3
    assert analyst_cal["factor"] < researcher_cal["factor"]
    q.db.close()


def test_calibration_ignores_legacy_metric_version(tmp_path, monkeypatch):
    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "queue.db")
    q = TaskQueue()
    q.db.execute(
        """
        INSERT INTO planner_action_outcomes
        (child_task_id, parent_task_id, action_role, expected_evidence_gain,
         action_cost, action_efficiency, actual_evidence_gain, novelty,
         novel_atom_count, atom_count, prediction_error, observed_at, metric_version)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        """,
        ("legacy-child", "legacy-parent", "analyst", 0.8, 0.35, 2.0,
         0.0, 0.0, 0, 10, -0.8, "2026-09-27T00:00:00+00:00"),
    )
    q.db.commit()
    calibration = q.action_calibration("analyst")
    assert calibration["samples"] == 0
    assert calibration["factor"] == 1.0
    q.db.close()


def test_realized_evidence_gain_uses_novelty_not_atom_density(tmp_path, monkeypatch):
    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "queue.db")
    from orchestrator.master import AutonomousPlanner
    q = TaskQueue()
    planner = AutonomousPlanner(q)
    monkeypatch.setattr(
        planner,
        "novelty_against_history",
        lambda task, history: (0.333, 4, 12),
    )
    actual, novelty, novel_count, atom_count = planner.realized_evidence_gain({}, [])
    assert actual == 0.333
    assert (novelty, novel_count, atom_count) == (0.333, 4, 12)
    q.db.close()


def test_action_outcome_summary_excludes_legacy_metrics(tmp_path, monkeypatch):
    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "queue.db")
    q = TaskQueue()
    q.db.execute(
        """
        INSERT INTO planner_action_outcomes
        (child_task_id, parent_task_id, action_role, expected_evidence_gain,
         action_cost, action_efficiency, actual_evidence_gain, novelty,
         novel_atom_count, atom_count, prediction_error, observed_at, metric_version)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        ("legacy", "legacy-parent", "analyst", 0.8, 0.35, 2.0, 0.0,
         0.0, 0, 10, -0.8, "2026-09-27T00:00:00+00:00", 1),
    )
    q.db.execute(
        """
        INSERT INTO planner_action_outcomes
        (child_task_id, parent_task_id, action_role, expected_evidence_gain,
         action_cost, action_efficiency, actual_evidence_gain, novelty,
         novel_atom_count, atom_count, prediction_error, observed_at, metric_version)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        ("current", "current-parent", "analyst", 0.8, 0.35, 2.0, 0.6,
         0.6, 1, 1, -0.2, "2026-09-27T00:00:01+00:00", 2),
    )
    q.db.commit()
    summary = q.action_outcome_summary()
    assert summary["samples"] == 1
    assert summary["by_role"]["analyst"]["actual"] == 0.6
    q.db.close()
