import json

import pytest

import shared.queue as queue_module
from aegisforge import task_main
from shared.queue import TaskQueue
from shared.research_case import CaseStatus, ExecutionMode, ResearchCase


def make_case():
    return ResearchCase(
        case_id="case-cli-new-round",
        target_repository="owner/repository",
        target_commit="a" * 40,
        scope_url="https://example.com/security-scope",
        scope_digest="b" * 64,
        scope_reviewed_on="2026-10-16",
        hypothesis="A falsifiable local test hypothesis",
        attacker_capability="Unprivileged caller of the local test harness",
        expected_invariant="The control case remains unchanged",
        falsification_criteria="Reject if the control case changes",
        execution_mode=ExecutionMode.LOCAL,
        status=CaseStatus.READY,
    )


@pytest.fixture
def registered_case(tmp_path, monkeypatch):
    db_path = tmp_path / "queue.db"
    monkeypatch.setattr(queue_module, "DB_PATH", db_path)
    queue = TaskQueue(db_path=db_path)
    case = make_case()
    queue.register_research_case(case)
    queue.db.close()
    return db_path, case


def test_cli_new_round_requires_explicit_confirmation(registered_case, capsys):
    db_path, case = registered_case

    with pytest.raises(SystemExit) as exc:
        task_main([
            "case", "new-round", "--case-id", case.case_id,
            "--db", str(db_path),
        ])

    assert exc.value.code == 2
    queue = TaskQueue(db_path=db_path)
    try:
        assert queue.db.execute(
            "SELECT COUNT(*) FROM queue WHERE research_case_id = ?",
            (case.case_id,),
        ).fetchone()[0] == 0
    finally:
        queue.db.close()


def test_cli_new_round_creates_exactly_one_case_bound_round(registered_case, capsys):
    db_path, case = registered_case

    result_code = task_main([
        "case", "new-round", "--case-id", case.case_id,
        "--confirm-new-round", "--db", str(db_path),
    ])

    assert result_code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "queued"
    assert result["case_id"] == case.case_id
    assert result["round_number"] == 1

    queue = TaskQueue(db_path=db_path)
    try:
        rows = queue.db.execute(
            "SELECT id, research_case_id, round_id, status FROM queue "
            "WHERE research_case_id = ?",
            (case.case_id,),
        ).fetchall()
        assert len(rows) == 1
        assert rows[0][1] == case.case_id
        assert rows[0][2] == result["round_id"]
        assert rows[0][3] == "pending"

        ledger = queue.db.execute(
            "SELECT round_id, case_id, round_number, root_task_id "
            "FROM research_case_rounds WHERE case_id = ?",
            (case.case_id,),
        ).fetchall()
        assert len(ledger) == 1
        assert ledger[0] == (
            result["round_id"], case.case_id, 1, result["root_task_id"]
        )
    finally:
        queue.db.close()


def test_cli_new_round_refuses_to_duplicate_active_work(registered_case, capsys):
    db_path, case = registered_case
    args = [
        "case", "new-round", "--case-id", case.case_id,
        "--confirm-new-round", "--db", str(db_path),
    ]

    assert task_main(args) == 0
    assert task_main(args) == 2
    output = capsys.readouterr().out.splitlines()
    rejection = json.loads(output[-1])
    assert rejection["status"] == "rejected"
    assert "case_round_already_active" in rejection["reason"]

    queue = TaskQueue(db_path=db_path)
    try:
        assert queue.db.execute(
            "SELECT COUNT(*) FROM queue WHERE research_case_id = ?",
            (case.case_id,),
        ).fetchone()[0] == 1
        assert queue.db.execute(
            "SELECT COUNT(*) FROM research_case_rounds WHERE case_id = ?",
            (case.case_id,),
        ).fetchone()[0] == 1
    finally:
        queue.db.close()
