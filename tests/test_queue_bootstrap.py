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
    assert summary["samples"] == 1
    assert summary["by_role"]["analyst"]["samples"] == 1
    q.db.close()
