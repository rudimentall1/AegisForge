from shared.queue import TaskQueue


def test_verified_outcome_feedback_updates_originating_planner_action(tmp_path):
    db_path = tmp_path / "queue.db"
    queue = TaskQueue(str(db_path))

    planner_id = queue.add(
        description="execute a validated staging action",
        role="developer",
    )
    queue.mark_planner_decision(
        planner_id,
        decision="EXECUTE",
        action_role="developer",
        expected_evidence_gain=0.6,
        action_cost=0.2,
        action_efficiency=3.0,
    )
    child_id = queue.add(
        description="executor handoff",
        role="executor",
        parent_task_id=planner_id,
        allow_failed_parent=True,
    )

    queue.claim("executor-test", role="executor")
    queue.finish(child_id, {"status": "PROVEN"})

    assert queue.record_verified_outcome_feedback(child_id, "PROVEN") is True

    row = queue.db.execute(
        "SELECT action_role, expected_evidence_gain, actual_evidence_gain, "
        "prediction_error, novelty, novel_atom_count, atom_count "
        "FROM planner_action_outcomes WHERE child_task_id = ?",
        (child_id,),
    ).fetchone()

    assert row is not None
    assert row[0] == "developer"
    assert row[1] == 0.6
    assert row[2] == 1.0
    assert row[3] == 0.4
    assert row[4] == 1.0
    assert row[5:] == (1, 1)

    assert queue.record_verified_outcome_feedback(child_id, "PROVEN") is False


def test_unproven_outcome_does_not_calibrate(tmp_path):
    db_path = tmp_path / "queue.db"
    queue = TaskQueue(str(db_path))

    planner_id = queue.add(description="action", role="developer")
    queue.mark_planner_decision(
        planner_id,
        decision="EXECUTE",
        action_role="developer",
        expected_evidence_gain=0.6,
    )
    child_id = queue.add(
        description="executor",
        role="executor",
        parent_task_id=planner_id,
        allow_failed_parent=True,
    )

    queue.claim("executor-test", role="executor")
    queue.finish(child_id, {"status": "EXECUTED"})

    assert queue.record_verified_outcome_feedback(child_id, "EXECUTED") is False
    assert queue.action_outcome_summary()["samples"] == 0