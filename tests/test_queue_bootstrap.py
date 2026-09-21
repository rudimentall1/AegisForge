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
