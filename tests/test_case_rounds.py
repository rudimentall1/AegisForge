import json

import pytest

import shared.queue as queue_module
from shared.queue import TaskQueue
from shared.case_rounds import CaseRoundError, start_case_round, diagnose_case_state
from shared.research_case import CaseStatus, ExecutionMode, ResearchCase


def make_case(*, status=CaseStatus.READY, case_id="case-round-test"):
    return ResearchCase(
        case_id=case_id,
        target_repository="owner/repository",
        target_commit="a" * 40,
        scope_url="https://example.com/security-scope",
        scope_digest="b" * 64,
        scope_reviewed_on="2026-10-16",
        hypothesis="A falsifiable synthetic test hypothesis",
        attacker_capability="Unprivileged caller of the local test harness",
        expected_invariant="The control case must remain unchanged",
        falsification_criteria="Reject if the control case changes",
        execution_mode=ExecutionMode.LOCAL,
        status=status,
    )


@pytest.fixture
def queue(tmp_path, monkeypatch):
    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "queue.db")
    q = TaskQueue()
    yield q
    q.db.close()


def test_start_case_round_creates_one_case_bound_root_and_ledger_row(queue):
    case = make_case()
    queue.register_research_case(case)

    result = start_case_round(queue, case.case_id)

    assert result["status"] == "queued"
    assert result["round_number"] == 1
    task = queue.get(result["root_task_id"])
    assert task[2] == "pending"
    assert task[7] == "source_researcher"
    assert task[8] is None
    assert task[12] == case.case_id
    assert result["round_id"] in task[1]
    # Round identity must be queryable from structured queue metadata, not only
    # recoverable by parsing the free-form task description or joining the ledger.
    root_round_id = queue.db.execute(
        "SELECT round_id FROM queue WHERE id = ?",
        (result["root_task_id"],),
    ).fetchone()[0]
    assert root_round_id == result["round_id"]
    row = queue.db.execute(
        "SELECT round_id, case_id, round_number, root_task_id "
        "FROM research_case_rounds"
    ).fetchone()
    assert row == (
        result["round_id"], case.case_id, 1, result["root_task_id"]
    )


def test_round_lifecycle_tracks_root_and_child_queue_transitions(queue):
    case = make_case()
    queue.register_research_case(case)
    started = start_case_round(queue, case.case_id)
    round_id = started["round_id"]
    root_id = started["root_task_id"]

    def round_state():
        return queue.db.execute(
            "SELECT status, started_at, finished_at FROM research_case_rounds "
            "WHERE case_id = ? AND round_id = ?",
            (case.case_id, round_id),
        ).fetchone()

    assert round_state() == ("QUEUED", None, None)

    claimed_root = queue.claim("lifecycle-test-root", role="source_researcher")
    assert claimed_root[0] == root_id
    running = round_state()
    assert running[0] == "RUNNING"
    assert running[1] is not None
    assert running[2] is None

    child_id = queue.add(
        "lifecycle child task",
        role="crypto_analyst",
        parent_task_id=root_id,
    )
    queue.finish(root_id, {"stage": "root complete"})
    waiting_for_child = round_state()
    assert waiting_for_child[0] == "RUNNING"
    assert waiting_for_child[1] is not None
    assert waiting_for_child[2] is None

    claimed_child = queue.claim("lifecycle-test-child", role="crypto_analyst")
    assert claimed_child[0] == child_id
    queue.finish(child_id, {"stage": "child complete"})
    completed = round_state()
    assert completed[0] == "COMPLETED"
    assert completed[1] is not None
    assert completed[2] is not None


def test_round_lifecycle_records_failed_execution(queue):
    case = make_case()
    queue.register_research_case(case)
    started = start_case_round(queue, case.case_id)
    root_id = started["root_task_id"]

    claimed = queue.claim("lifecycle-test-failure", role="source_researcher")
    assert claimed[0] == root_id
    queue.fail(root_id, {"reason": "synthetic failure"})

    status, started_at, finished_at = queue.db.execute(
        "SELECT status, started_at, finished_at FROM research_case_rounds "
        "WHERE case_id = ? AND round_id = ?",
        (case.case_id, started["round_id"]),
    ).fetchone()
    assert status == "FAILED"
    assert started_at is not None
    assert finished_at is not None


def test_start_case_round_rejects_when_any_case_task_is_active(queue):
    case = make_case()
    queue.register_research_case(case)
    existing = queue.add("existing active child", "analyst", research_case_id=case.case_id)

    with pytest.raises(CaseRoundError, match="case_round_already_active"):
        start_case_round(queue, case.case_id)

    assert queue.db.execute(
        "SELECT COUNT(*) FROM queue WHERE research_case_id = ?",
        (case.case_id,),
    ).fetchone()[0] == 1
    assert queue.get(existing)[2] == "pending"


def test_start_case_round_allows_explicit_new_round_after_previous_round_is_terminal(queue):
    case = make_case()
    queue.register_research_case(case)
    first = start_case_round(queue, case.case_id)
    queue.db.execute(
        "UPDATE queue SET status='completed', finished_at='2026-10-16T00:00:00+00:00' WHERE id=?",
        (first["root_task_id"],),
    )
    queue.db.commit()

    second = start_case_round(queue, case.case_id)

    assert second["round_number"] == 2
    assert second["round_id"] != first["round_id"]
    assert second["root_task_id"] != first["root_task_id"]
    assert queue.db.execute(
        "SELECT COUNT(*) FROM research_case_rounds WHERE case_id = ?",
        (case.case_id,),
    ).fetchone()[0] == 2


def test_start_case_round_rejects_unregistered_or_terminal_case(queue):
    with pytest.raises(CaseRoundError, match="research_case_not_registered"):
        start_case_round(queue, "missing-case")

    case = make_case(status=CaseStatus.REJECTED)
    queue.register_research_case(case)
    with pytest.raises(CaseRoundError, match="research_case_not_runnable"):
        start_case_round(queue, case.case_id)

    assert queue.db.execute("SELECT COUNT(*) FROM queue").fetchone()[0] == 0


def test_child_task_inherits_parent_round_identity(queue):
    case = make_case()
    queue.register_research_case(case)
    root = start_case_round(queue, case.case_id)
    child_id = queue.add(
        "child task in the same round",
        role="crypto_analyst",
        parent_task_id=root["root_task_id"],
    )

    row = queue.db.execute(
        "SELECT research_case_id, round_id FROM queue WHERE id = ?",
        (child_id,),
    ).fetchone()
    assert row == (case.case_id, root["round_id"])


def test_child_task_rejects_explicit_different_round_identity(queue):
    case = make_case()
    queue.register_research_case(case)
    root = start_case_round(queue, case.case_id)

    with pytest.raises(ValueError, match="research_case_round_parent_mismatch"):
        queue.add(
            "child task attempting to cross rounds",
            role="crypto_analyst",
            parent_task_id=root["root_task_id"],
            round_id="different-round-id",
        )

    assert queue.db.execute(
        "SELECT COUNT(*) FROM queue WHERE parent_task_id = ?",
        (root["root_task_id"],),
    ).fetchone()[0] == 0




def test_diagnose_case_state_reports_idle_until_operator_starts_round(queue):
    case = make_case()
    queue.register_research_case(case)

    result = diagnose_case_state(queue, case.case_id)

    assert result["state"] == "idle_awaiting_input"
    assert result["reason"] == "explicit_operator_action_required"
    assert result["counts"]["pending"] == 0


def test_diagnose_case_state_reports_active_and_then_idle(queue):
    case = make_case()
    queue.register_research_case(case)
    round_result = start_case_round(queue, case.case_id)

    assert diagnose_case_state(queue, case.case_id)["state"] == "active"

    queue.db.execute(
        "UPDATE queue SET status='completed', finished_at='2026-10-16T00:00:00+00:00' WHERE id=?",
        (round_result["root_task_id"],),
    )
    queue.db.commit()

    result = diagnose_case_state(queue, case.case_id)
    assert result["state"] == "idle_awaiting_input"
    assert result["counts"]["completed"] == 1


def test_diagnose_case_state_prioritizes_open_human_review_over_failed_work(queue):
    case = make_case()
    queue.register_research_case(case)
    task_id = queue.add("failed test task", "analyst", research_case_id=case.case_id)
    queue.db.execute(
        "UPDATE queue SET status='failed', finished_at='2026-10-16T00:00:00+00:00' WHERE id=?",
        (task_id,),
    )
    queue.db.execute(
        "INSERT INTO pending_human_review (id, case_id, task_id, reason, status, created_at) "
        "VALUES ('review-1', ?, ?, 'manual decision required', 'OPEN', '2026-10-16T00:00:00+00:00')",
        (case.case_id, task_id),
    )
    queue.db.commit()

    result = diagnose_case_state(queue, case.case_id)
    assert result["state"] == "blocked"
    assert result["reason"] == "human_review_required"
    assert result["open_reviews"] == 1


def test_diagnose_case_state_reports_terminal_case(queue):
    case = make_case(status=CaseStatus.INCONCLUSIVE)
    queue.register_research_case(case)

    result = diagnose_case_state(queue, case.case_id)
    assert result["state"] == "terminal"
    assert result["reason"] == "research_case_terminal:inconclusive"


def test_diagnose_case_state_reports_missing_case_as_blocked(queue):
    result = diagnose_case_state(queue, "missing-case")
    assert result["state"] == "blocked"
    assert result["reason"] == "research_case_not_registered"




def test_case_round_cli_requires_explicit_confirmation(queue, monkeypatch, capsys):
    from shared.case_rounds import main as case_round_main

    case = make_case(case_id="case-round-cli-confirmation")
    queue.register_research_case(case)

    with pytest.raises(SystemExit) as exc:
        case_round_main(["--case-id", case.case_id])
    assert exc.value.code == 2
    assert queue.db.execute(
        "SELECT COUNT(*) FROM queue WHERE research_case_id = ?",
        (case.case_id,),
    ).fetchone()[0] == 0


def test_case_round_cli_creates_exactly_one_confirmed_round(queue, monkeypatch, capsys):
    from shared.case_rounds import main as case_round_main

    case = make_case(case_id="case-round-cli-confirmed")
    queue.register_research_case(case)

    assert case_round_main([
        "--case-id", case.case_id, "--confirm-new-round",
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "queued"
    assert result["case_id"] == case.case_id
    assert result["round_number"] == 1

    rows = queue.db.execute(
        "SELECT id, round_id FROM queue WHERE research_case_id = ?",
        (case.case_id,),
    ).fetchall()
    assert rows == [(result["root_task_id"], result["round_id"])]

    # A second CLI invocation must fail closed while that round is active.
    assert case_round_main([
        "--case-id", case.case_id, "--confirm-new-round",
    ]) == 2
    second = json.loads(capsys.readouterr().out)
    assert second["status"] == "rejected"
    assert second["reason"].startswith("case_round_already_active:")
    assert queue.db.execute(
        "SELECT COUNT(*) FROM queue WHERE research_case_id = ?",
        (case.case_id,),
    ).fetchone()[0] == 1



def test_start_case_round_fails_closed_on_unresolved_failed_task(queue):
    case = make_case(case_id="case-round-failed-task-block")
    queue.register_research_case(case)
    task_id = queue.add("failed research task", "source_researcher", research_case_id=case.case_id)
    queue.db.execute(
        "UPDATE queue SET status='failed', finished_at='2026-10-16T00:00:00+00:00' WHERE id=?",
        (task_id,),
    )
    queue.db.commit()

    with pytest.raises(CaseRoundError, match="case_round_blocked_failed_tasks"):
        start_case_round(queue, case.case_id)

    assert queue.db.execute(
        "SELECT COUNT(*) FROM queue WHERE research_case_id = ? AND role = 'source_researcher' AND parent_task_id IS NULL",
        (case.case_id,),
    ).fetchone()[0] == 1
    assert diagnose_case_state(queue, case.case_id)["reason"] == "failed_tasks_require_operator_review"


def test_start_case_round_fails_closed_on_open_human_review(queue):
    case = make_case(case_id="case-round-human-review-block")
    queue.register_research_case(case)
    task_id = queue.add("review required task", "analyst", research_case_id=case.case_id)
    # Keep the review open while removing the active-task blocker, so this test
    # exercises the human-review guard specifically.
    queue.db.execute(
        "UPDATE queue SET status='completed', finished_at='2026-10-16T00:00:00+00:00' WHERE id=?",
        (task_id,),
    )
    queue.db.execute(
        "INSERT INTO pending_human_review (id, case_id, task_id, reason, status, created_at) "
        "VALUES ('review-block-1', ?, ?, 'operator review required', 'OPEN', '2026-10-16T00:00:00+00:00')",
        (case.case_id, task_id),
    )
    queue.db.commit()

    with pytest.raises(CaseRoundError, match="case_round_blocked_human_review"):
        start_case_round(queue, case.case_id)

    assert queue.db.execute(
        "SELECT COUNT(*) FROM queue WHERE research_case_id = ? AND role = 'source_researcher' AND parent_task_id IS NULL",
        (case.case_id,),
    ).fetchone()[0] == 0
    assert diagnose_case_state(queue, case.case_id)["reason"] == "human_review_required"


@pytest.mark.parametrize(
    ("lifecycle", "expected_state", "expected_exit"),
    [
        ("idle", "idle_awaiting_input", 0),
        ("active", "active", 0),
        ("failed", "blocked", 2),
        ("terminal", "terminal", 0),
    ],
)
def test_case_diagnose_cli_exit_contract(
    queue, capsys, lifecycle, expected_state, expected_exit
):
    """The supported CLI exposes machine-readable lifecycle state and exit codes."""
    from aegisforge import task_main

    case_status = (
        CaseStatus.INCONCLUSIVE if lifecycle == "terminal" else CaseStatus.READY
    )
    case = make_case(
        case_id=f"case-cli-diagnose-{lifecycle}",
        status=case_status,
    )
    queue.register_research_case(case)
    if lifecycle == "active":
        start_case_round(queue, case.case_id)
    elif lifecycle == "failed":
        task_id = queue.add(
            "failed synthetic task",
            "source_researcher",
            research_case_id=case.case_id,
        )
        queue.db.execute(
            "UPDATE queue SET status='failed', finished_at='2026-10-16T00:00:00+00:00' WHERE id=?",
            (task_id,),
        )
        queue.db.commit()

    db_path = queue.db.execute("PRAGMA database_list").fetchone()[2]
    exit_code = task_main([
        "case", "diagnose", "--case-id", case.case_id, "--db", db_path,
    ])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == expected_exit
    assert payload["state"] == expected_state
    if lifecycle == "failed":
        assert payload["reason"] == "failed_tasks_require_operator_review"
