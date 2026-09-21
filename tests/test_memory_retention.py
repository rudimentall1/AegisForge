import json

import shared.memory as memory_module
from shared.memory import Memory


class FakeTask:
    def __init__(self, task_id, created_at, result):
        self.task_id = task_id
        self.description = f"task-{task_id}"
        self.status = "completed"
        self.result = result
        self.created_at = created_at


def test_memory_result_is_bounded(tmp_path, monkeypatch):
    db_path = tmp_path / "memory.db"
    monkeypatch.setattr(memory_module, "DB_PATH", db_path)

    memory = Memory()
    payload = {"evidence": "x" * 20000}

    memory.save_task(FakeTask("1", "2026-01-01T00:00:00+00:00", payload))

    stored = memory.db.execute(
        "SELECT result FROM tasks WHERE task_id = '1'"
    ).fetchone()[0]

    assert len(stored.encode("utf-8")) <= memory_module.MAX_RESULT_BYTES + 32
    memory.close()


def test_memory_task_count_is_bounded(tmp_path, monkeypatch):
    db_path = tmp_path / "memory.db"
    monkeypatch.setattr(memory_module, "DB_PATH", db_path)

    memory = Memory()

    for index in range(memory_module.MAX_RETAINED_TASKS + 25):
        memory.save_task(
            FakeTask(
                str(index),
                f"2026-01-01T00:{index // 60:02d}:{index % 60:02d}+00:00",
                {"index": index},
            )
        )

    count = memory.db.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
    assert count == memory_module.MAX_RETAINED_TASKS

    newest = memory.db.execute(
        "SELECT task_id FROM tasks ORDER BY created_at DESC LIMIT 1"
    ).fetchone()[0]
    assert newest == str(memory_module.MAX_RETAINED_TASKS + 24)

    memory.close()
