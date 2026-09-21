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
