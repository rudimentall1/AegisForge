import pytest

import shared.queue as queue_module
from shared.queue import TaskQueue
from shared.case_rounds import CaseRoundError, start_case_round
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
