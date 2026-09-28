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


def test_queue_persists_structured_capability_intent(tmp_path, monkeypatch):
    db_path = tmp_path / "intent.db"
    monkeypatch.setattr(queue_module, "DB_PATH", db_path)
    q = TaskQueue()

    intent = {"action": "deploy", "destination": "staging", "irreversible": True}
    task_id = q.add("deploy safely", role="developer", capability_intent=intent)
    row = q.claim("worker-1", role="developer")

    assert row[0] == task_id
    assert row[10] == '{"action":"deploy","destination":"staging","irreversible":true}'
    q.db.close()


def test_queue_can_claim_evidence_child_from_failed_capability_parent(tmp_path, monkeypatch):
    db_path = tmp_path / "failed_parent.db"
    monkeypatch.setattr(queue_module, "DB_PATH", db_path)
    q = TaskQueue()

    parent = q.add("blocked action", role="developer")
    q.claim("worker-1", role="developer")
    q.fail(parent, {
        "error_type": "CapabilityEvidenceRequired",
        "decision": "REQUIRE_EVIDENCE",
    })

    child = q.add(
        "verify prerequisites",
        role="validator",
        parent_task_id=parent,
        capability_intent={"action": "verify"},
        allow_failed_parent=True,
    )

    claimed = q.claim("worker-2", role="validator")
    assert claimed[0] == child
    assert claimed[10] == '{"action":"verify"}'
    assert claimed[11] == 1
    q.db.close()


def test_requeue_failed_allows_retry_of_capability_evidence_child(tmp_path, monkeypatch):
    db_path = tmp_path / "failed_parent_retry.db"
    monkeypatch.setattr(queue_module, "DB_PATH", db_path)
    q = TaskQueue()

    parent = q.add("blocked action", role="developer")
    q.claim("worker-1", role="developer")
    q.fail(parent, {"error_type": "CapabilityEvidenceRequired"})

    child = q.add(
        "verify prerequisites",
        role="validator",
        parent_task_id=parent,
        capability_intent={"action": "verify"},
        allow_failed_parent=True,
    )
    q.claim("worker-2", role="validator")
    q.fail(child, {"error_type": "RuntimeError", "error": "temporary"})

    assert q.requeue_failed(child, max_retries=1) is True
    assert q.db.execute("select status from queue where id=?", (child,)).fetchone()[0] == "pending"
    q.db.close()
