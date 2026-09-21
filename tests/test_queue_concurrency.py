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


def test_compact_completed_results_preserves_active_branch_context(
    tmp_path,
    monkeypatch,
):
    db_path = tmp_path / "retention.db"
    monkeypatch.setattr(queue_module, "DB_PATH", db_path)

    q = TaskQueue()

    root = q.add("root", role="researcher")
    root_row = q.claim("worker-1")
    q.finish(root, {"evidence_atoms": ["finding:root"], "repositories": ["org/root"]})
    q.mark_planner_decision(root, "CONTINUE", 0.8, "root-fp")

    child = q.add("child", role="analyst", parent_task_id=root)
    child_row = q.claim("worker-2")
    q.finish(child, {"evidence_atoms": ["finding:child"]})
    q.mark_planner_decision(child, "COMPLETE", 0.9, "child-fp")

    # Make both records old enough without relying on wall-clock sleeps.
    q.db.execute(
        "UPDATE queue SET finished_at = '2020-01-01T00:00:00+00:00'"
    )
    q.db.commit()

    # The completed branch has no live frontier, so both raw results can be
    # compacted while the planner's durable evidence remains independent.
    compacted = q.compact_completed_results(
        older_than_days=0,
        keep_ancestor_depth=4,
    )

    assert compacted == 2
    assert q.get_result(root) is None
    assert q.get_result(child) is None

    q.db.close()


def test_compact_completed_results_keeps_pending_parent_result(
    tmp_path,
    monkeypatch,
):
    db_path = tmp_path / "retention_pending.db"
    monkeypatch.setattr(queue_module, "DB_PATH", db_path)

    q = TaskQueue()

    root = q.add("root", role="researcher")
    q.claim("worker-1")
    q.finish(root, {"repositories": ["org/root"]})
    q.mark_planner_decision(root, "CONTINUE", 0.8, "root-fp")

    child = q.add("child", role="analyst", parent_task_id=root)

    q.db.execute(
        "UPDATE queue SET finished_at = '2020-01-01T00:00:00+00:00'"
    )
    q.db.commit()

    compacted = q.compact_completed_results(
        older_than_days=0,
        keep_ancestor_depth=4,
    )

    assert compacted == 0
    assert q.get_result(root) == {"repositories": ["org/root"]}

    q.db.close()
