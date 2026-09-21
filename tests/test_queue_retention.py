import shared.queue as queue_module
from shared.queue import TaskQueue


def test_queue_description_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "queue.db")
    q = TaskQueue()
    task_id = q.add("x" * (queue_module.MAX_DESCRIPTION_BYTES + 500), role="developer")
    stored = q.db.execute(
        "SELECT description FROM queue WHERE id = ?", (task_id,)
    ).fetchone()[0]
    assert len(stored.encode("utf-8")) <= queue_module.MAX_DESCRIPTION_BYTES + 32
    q.db.close()


def test_queue_history_compaction_keeps_recent_rows(tmp_path, monkeypatch):
    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "queue.db")
    q = TaskQueue()
    for i in range(12):
        task_id = q.add(f"task-{i}", role="developer")
        q.db.execute(
            "UPDATE queue SET status='completed', finished_at=? WHERE id=?",
            (f"2026-01-01T00:{i:02d}:00+00:00", task_id),
        )
    q.db.commit()

    deleted = q.compact_history(keep_recent=5, limit=100)

    assert deleted == 7
    assert q.db.execute("SELECT COUNT(*) FROM queue").fetchone()[0] == 5
    q.db.close()


def test_queue_compaction_bounds_existing_descriptions(tmp_path, monkeypatch):
    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "queue.db")
    q = TaskQueue()
    task_id = q.add("short", role="developer")
    huge = "x" * (queue_module.MAX_DESCRIPTION_BYTES + 500)
    q.db.execute("UPDATE queue SET description=? WHERE id=?", (huge, task_id))
    q.db.commit()

    q.compact_history(keep_recent=5, limit=100)

    stored = q.db.execute(
        "SELECT description FROM queue WHERE id = ?", (task_id,)
    ).fetchone()[0]
    assert len(stored.encode("utf-8")) <= queue_module.MAX_DESCRIPTION_BYTES
    q.db.close()
