import shared.queue as queue_module
from shared.queue import TaskQueue


def test_queue_connections_use_busy_timeout_and_claim_distinct_tasks(
    tmp_path,
    monkeypatch,
):
    db_path = tmp_path / "queue.db"
    monkeypatch.setattr(queue_module, "DB_PATH", db_path)

    first = TaskQueue()
    second = TaskQueue()

    task_one = first.add("one", role="developer")
    task_two = first.add("two", role="developer")

    assert first.db.execute("PRAGMA busy_timeout").fetchone()[0] == 30000
    assert second.db.execute("PRAGMA busy_timeout").fetchone()[0] == 30000

    claimed_one = first.claim("worker-1", role="developer")
    claimed_two = second.claim("worker-2", role="developer")

    assert claimed_one[0] == task_one
    assert claimed_two[0] == task_two

    first.db.close()
    second.db.close()
