import json
from datetime import datetime, timedelta, timezone

import orchestrator.master as master_module
from shared.queue import TaskQueue as RealTaskQueue
from shared.research_case import ResearchCase, RoundSpec


def make_case(case_id="bootstrap-case-001", status="ready", rounds=()):
    return ResearchCase(
        case_id=case_id,
        target_repository="example/project",
        target_commit="a" * 40,
        scope_url="https://example.com/scope",
        scope_digest="b" * 64,
        scope_reviewed_on="2026-10-16",
        hypothesis="A bounded local test may violate an accounting invariant.",
        attacker_capability="An unprivileged caller can invoke the public method.",
        expected_invariant="The recorded balance equals the independently calculated balance.",
        falsification_criteria="Counter-tests preserve the invariant for all tested transitions.",
        execution_mode="local",
        status=status,
        allowed_techniques=("source_pattern", "synthetic_check"),
        rounds=rounds,
    )


def make_master(tmp_path, monkeypatch):
    db_path = tmp_path / "queue.db"
    monkeypatch.setattr(
        master_module,
        "TaskQueue",
        lambda: RealTaskQueue(db_path=db_path),
    )
    master = master_module.MasterOrchestrator()
    return master, master.queue


def register_case(queue, case=None):
    case = case or make_case()
    queue.register_research_case(case)
    return case.case_id


def add_root(queue, case_id, role="source_researcher", status="completed", decision="COMPLETE"):
    task_id = queue.add(
        description="bounded synthetic forensic task",
        role=role,
        research_case_id=case_id,
    )
    queue.db.execute(
        "UPDATE queue SET status = ?, planner_decision = ? WHERE id = ?",
        (status, decision, task_id),
    )
    queue.db.commit()
    return task_id


def open_reviews(queue, case_id):
    return queue.db.execute(
        "SELECT id, status FROM pending_human_review WHERE case_id = ?",
        (case_id,),
    ).fetchall()


def test_bootstrap_creates_review_when_all_branches_terminal(tmp_path, monkeypatch):
    master, queue = make_master(tmp_path, monkeypatch)
    case_id = register_case(queue)
    add_root(queue, case_id)

    assert master.bootstrap() is False
    reviews = queue.db.execute(
        "SELECT status FROM pending_human_review WHERE case_id = ? AND reason = ?",
        (case_id, "all_branches_terminal:roots=1"),
    ).fetchall()
    assert reviews == [("OPEN",)]
    queue.db.close()


def test_bootstrap_does_not_create_review_when_branch_active(tmp_path, monkeypatch):
    master, queue = make_master(tmp_path, monkeypatch)
    case_id = register_case(queue)
    root_id = add_root(queue, case_id)
    queue.add(
        description="active child",
        role="crypto_analyst",
        parent_task_id=root_id,
    )

    master.bootstrap()
    assert open_reviews(queue, case_id) == []
    queue.db.close()


def test_bootstrap_creates_root_when_none_exists(tmp_path, monkeypatch):
    master, queue = make_master(tmp_path, monkeypatch)
    case_id = register_case(queue)

    assert master.bootstrap() is True
    roots = queue.db.execute(
        """
        SELECT role, research_case_id FROM queue
        WHERE parent_task_id IS NULL AND research_case_id = ?
        """,
        (case_id,),
    ).fetchall()
    assert roots == [("source_researcher", case_id)]
    queue.db.close()


def test_bootstrap_considers_all_root_roles(tmp_path, monkeypatch):
    master, queue = make_master(tmp_path, monkeypatch)
    case_id = register_case(queue)
    add_root(queue, case_id, role="crypto_analyst")

    master.bootstrap()
    reviews = queue.db.execute(
        "SELECT status FROM pending_human_review WHERE case_id = ? AND reason = ?",
        (case_id, "all_branches_terminal:roots=1"),
    ).fetchall()
    assert reviews == [("OPEN",)]
    queue.db.close()


def test_bootstrap_does_not_repeat_review_creation(tmp_path, monkeypatch):
    master, queue = make_master(tmp_path, monkeypatch)
    case_id = register_case(queue)
    add_root(queue, case_id)
    queue.create_human_review(case_id, "pre-existing")

    master.bootstrap()
    count_before = len(open_reviews(queue, case_id))
    master.bootstrap()
    count_after = len(open_reviews(queue, case_id))

    assert count_after == count_before
    assert queue.db.execute(
        "SELECT COUNT(*) FROM pending_human_review "
        "WHERE case_id = ? AND status = 'OPEN' AND reason = ?",
        (case_id, "all_branches_terminal:roots=1"),
    ).fetchone()[0] == 1
    assert queue.db.execute(
        "SELECT COUNT(*) FROM pending_human_review "
        "WHERE case_id = ? AND status = 'OPEN' AND reason = ?",
        (case_id, "pre-existing"),
    ).fetchone()[0] == 1
    assert count_after == 2
    queue.db.close()


def test_bootstrap_does_not_duplicate_same_reason(tmp_path, monkeypatch):
    master, queue = make_master(tmp_path, monkeypatch)
    case_id = register_case(queue)
    add_root(queue, case_id)
    reason = "all_branches_terminal:roots=1"
    queue.create_human_review(case_id, reason)

    master.bootstrap()
    master.bootstrap()

    assert queue.db.execute(
        "SELECT COUNT(*) FROM pending_human_review "
        "WHERE case_id = ? AND status = 'OPEN' AND reason = ?",
        (case_id, reason),
    ).fetchone()[0] == 1
    queue.db.close()


def test_bootstrap_legacy_path_unchanged(tmp_path, monkeypatch):
    master, queue = make_master(tmp_path, monkeypatch)
    assert master.bootstrap() is True
    legacy_roots = queue.db.execute(
        "SELECT role FROM queue WHERE parent_task_id IS NULL"
    ).fetchall()
    assert legacy_roots == [("researcher",)]
    queue.db.close()

    master, queue = make_master(tmp_path / "existing", monkeypatch)
    queue.add("existing planner work", role="researcher")
    assert master.bootstrap() is False
    queue.db.close()



def make_round(round_id="round-001", technique="source_pattern", days=30, priority=0):
    return RoundSpec(
        round_id=round_id,
        technique=technique,
        hypothesis="A bounded synthetic check may reveal a reproducible invariant violation.",
        expected_evidence_atoms=("source location", "counter-test output"),
        falsification_criteria="A counter-test preserves the invariant under the same preconditions.",
        priority=priority,
        disclosure_deadline_days=days,
    )


def test_bootstrap_creates_root_and_transparency_for_each_round(tmp_path, monkeypatch):
    master, queue = make_master(tmp_path, monkeypatch)
    case = make_case(rounds=(
        make_round("round-low", "source_pattern", days=30, priority=1),
        make_round("round-high", "synthetic_check", days=30, priority=5),
    ))
    case_id = register_case(queue, case)

    assert master.bootstrap() is True
    roots = queue.db.execute(
        """
        SELECT round_id, role, research_case_id FROM queue
        WHERE parent_task_id IS NULL AND research_case_id = ?
        ORDER BY round_id
        """,
        (case_id,),
    ).fetchall()
    assert roots == [
        ("round-high", "source_researcher", case_id),
        ("round-low", "source_researcher", case_id),
    ]
    timelines = queue.db.execute(
        """
        SELECT round_id, technique, started_at, disclosure_deadline, status
        FROM round_transparency WHERE case_id = ? ORDER BY round_id
        """,
        (case_id,),
    ).fetchall()
    assert [row[0] for row in timelines] == ["round-high", "round-low"]
    assert timelines[0][1] == "synthetic_check"
    assert timelines[0][4] == "OPEN"
    started = datetime.fromisoformat(timelines[0][2])
    deadline = datetime.fromisoformat(timelines[0][3])
    assert timedelta(days=29, hours=23) < deadline - started <= timedelta(days=30)
    queue.db.close()


def test_terminal_round_records_completion_and_never_auto_confirms(tmp_path, monkeypatch):
    master, queue = make_master(tmp_path, monkeypatch)
    case_id = register_case(queue, make_case(rounds=(make_round(),)))

    assert master.bootstrap() is True
    root = queue.db.execute(
        "SELECT id FROM queue WHERE parent_task_id IS NULL AND round_id = ?",
        ("round-001",),
    ).fetchone()[0]
    queue.db.execute(
        "UPDATE queue SET status = 'completed', result = ? WHERE id = ?",
        (json.dumps({"research_validation": {"verdict": "REPRODUCED"}}), root),
    )
    queue.db.commit()

    assert master.bootstrap() is False
    row = queue.db.execute(
        """
        SELECT status, completed_at, verdict FROM round_transparency
        WHERE round_id = ?
        """,
        ("round-001",),
    ).fetchone()
    assert row[0] == "COMPLETED"
    assert row[1] is not None
    assert row[2] == "REPRODUCED"
    queue.db.close()


def test_expired_open_round_creates_deadline_review_while_branch_active(tmp_path, monkeypatch):
    master, queue = make_master(tmp_path, monkeypatch)
    case_id = register_case(queue, make_case(rounds=(make_round(),)))
    assert master.bootstrap() is True

    expired = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    queue.db.execute(
        "UPDATE round_transparency SET disclosure_deadline = ? WHERE round_id = ?",
        (expired, "round-001"),
    )
    queue.db.commit()

    assert master.bootstrap() is False
    review = queue.db.execute(
        "SELECT reason, status FROM pending_human_review WHERE case_id = ?",
        (case_id,),
    ).fetchone()
    assert review == ("deadline_exceeded:round-001", "OPEN")
    queue.db.close()



def test_bootstrap_repairs_partially_created_round_set(tmp_path, monkeypatch):
    master, queue = make_master(tmp_path, monkeypatch)
    case = make_case(rounds=(
        make_round("round-a", "source_pattern"),
        make_round("round-b", "synthetic_check"),
    ))
    case_id = register_case(queue, case)
    assert master.bootstrap() is True

    queue.db.execute("DELETE FROM queue WHERE round_id = ?", ("round-b",))
    queue.db.execute("DELETE FROM round_transparency WHERE round_id = ?", ("round-b",))
    queue.db.commit()

    assert master.bootstrap() is True
    roots = queue.db.execute(
        "SELECT round_id FROM queue WHERE parent_task_id IS NULL AND research_case_id = ? ORDER BY round_id",
        (case_id,),
    ).fetchall()
    timelines = queue.db.execute(
        "SELECT round_id FROM round_transparency WHERE case_id = ? ORDER BY round_id",
        (case_id,),
    ).fetchall()
    assert roots == [("round-a",), ("round-b",)]
    assert timelines == [("round-a",), ("round-b",)]
    queue.db.close()


def test_master_calls_new_complete_round(tmp_path, monkeypatch):
    master, queue = make_master(tmp_path, monkeypatch)
    case_id = register_case(queue, make_case(rounds=(make_round(),)))
    assert master.bootstrap() is True
    root = queue.db.execute(
        "SELECT id FROM queue WHERE parent_task_id IS NULL AND round_id = ?",
        ("round-001",),
    ).fetchone()[0]
    queue.db.execute(
        "UPDATE queue SET status = 'completed', result = ? WHERE id = ?",
        (json.dumps({"research_validation": {"verdict": "NOT_REPRODUCED"}}), root),
    )
    queue.db.commit()

    calls = []
    original = queue.complete_round

    def record_complete(round_id, completed_at, verdict):
        calls.append((round_id, completed_at, verdict))
        return original(round_id, completed_at, verdict)

    monkeypatch.setattr(queue, "complete_round", record_complete)
    assert master.bootstrap() is False
    assert len(calls) == 1
    assert calls[0][0] == "round-001"
    assert datetime.fromisoformat(calls[0][1]).tzinfo is not None
    assert calls[0][2] == "NOT_REPRODUCED"
    queue.db.close()


def test_master_uses_expired_rounds_for_review(tmp_path, monkeypatch):
    master, queue = make_master(tmp_path, monkeypatch)
    case_id = register_case(queue, make_case(rounds=(make_round(),)))
    assert master.bootstrap() is True
    root = queue.db.execute(
        "SELECT id FROM queue WHERE parent_task_id IS NULL AND round_id = ?",
        ("round-001",),
    ).fetchone()[0]
    queue.add(description="active child", role="crypto_analyst", parent_task_id=root)
    expired = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    queue.db.execute(
        "UPDATE round_transparency SET disclosure_deadline = ? WHERE round_id = ?",
        (expired, "round-001"),
    )
    queue.db.commit()

    calls = []
    original = queue.expired_rounds

    def record_expired(now):
        calls.append(now)
        return original(now)

    monkeypatch.setattr(queue, "expired_rounds", record_expired)
    assert master.bootstrap() is False
    assert calls and isinstance(calls[0], datetime)
    review = queue.db.execute(
        "SELECT reason FROM pending_human_review WHERE case_id = ?",
        (case_id,),
    ).fetchone()
    assert review == ("deadline_exceeded:round-001",)
    queue.db.close()


def test_complete_round_removed_from_queue(tmp_path, monkeypatch):
    _master, queue = make_master(tmp_path, monkeypatch)
    legacy_name = "complete_round_" + "transparency"
    assert hasattr(queue, "complete_round")
    assert not hasattr(queue, legacy_name)
    queue.db.close()


def test_multiple_expired_rounds_create_multiple_reviews(tmp_path, monkeypatch):
    master, queue = make_master(tmp_path, monkeypatch)
    case = make_case(rounds=(
        make_round("r1", "source_pattern"),
        make_round("r2", "synthetic_check"),
    ))
    case_id = register_case(queue, case)
    assert master.bootstrap() is True

    expired = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    queue.db.execute(
        "UPDATE round_transparency SET disclosure_deadline = ? WHERE case_id = ?",
        (expired, case_id),
    )
    queue.db.commit()

    assert master.bootstrap() is False
    reviews = queue.db.execute(
        "SELECT reason, status FROM pending_human_review WHERE case_id = ? ORDER BY created_at, id",
        (case_id,),
    ).fetchall()
    assert reviews == [
        ("deadline_exceeded:r1", "OPEN"),
        ("deadline_exceeded:r2", "OPEN"),
    ]
    queue.db.close()


def test_terminal_branch_and_expired_round_create_separate_reviews(tmp_path, monkeypatch):
    master, queue = make_master(tmp_path, monkeypatch)
    case_id = register_case(queue)
    add_root(queue, case_id, status="completed")

    expired = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    queue.create_round_transparency(
        round_id="r1",
        case_id=case_id,
        technique="source_pattern",
        started_at=(datetime.now(timezone.utc) - timedelta(days=31)).isoformat(),
        disclosure_deadline=expired,
    )

    assert master.bootstrap() is False
    reviews = queue.db.execute(
        "SELECT reason, status FROM pending_human_review WHERE case_id = ? ORDER BY created_at, id",
        (case_id,),
    ).fetchall()
    assert reviews == [
        ("deadline_exceeded:r1", "OPEN"),
        ("all_branches_terminal:roots=1", "OPEN"),
    ] or reviews == [
        ("all_branches_terminal:roots=1", "OPEN"),
        ("deadline_exceeded:r1", "OPEN"),
    ]
    queue.db.close()
