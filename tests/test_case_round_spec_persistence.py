"""Tests for separating planned round identity from runtime execution identity."""

import pytest

import shared.queue as queue_module
from shared.queue import TaskQueue
from shared.case_rounds import CaseRoundError, start_case_round
from shared.research_case import CaseStatus, ExecutionMode, ResearchCase, RoundSpec


def planned_case():
    return ResearchCase(
        case_id="planned-round-persistence",
        target_repository="owner/repository",
        target_commit="a" * 40,
        scope_url="https://example.com/security-scope",
        scope_digest="b" * 64,
        scope_reviewed_on="2026-10-16",
        hypothesis="Synthetic planned hypothesis",
        attacker_capability="Unprivileged local test harness",
        expected_invariant="Synthetic control remains unchanged",
        falsification_criteria="Reject if control changes",
        execution_mode=ExecutionMode.LOCAL,
        status=CaseStatus.READY,
        allowed_techniques=("source_pattern",),
        rounds=(RoundSpec(
            round_id="source-pattern-v1",
            technique="source_pattern",
            hypothesis="Synthetic planned hypothesis",
            expected_evidence_atoms=("source:synthetic",),
            falsification_criteria="Reject if control changes",
            disclosure_deadline_days=30,
        ),),
    )


@pytest.fixture
def queue(tmp_path, monkeypatch):
    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "queue.db")
    q = TaskQueue()
    yield q
    q.db.close()


def test_planned_case_requires_declared_round_spec_before_enqueue(queue):
    case = planned_case()
    queue.register_research_case(case)
    with pytest.raises(CaseRoundError, match="planned_case_requires_round_spec_id"):
        start_case_round(queue, case.case_id)
    with pytest.raises(CaseRoundError, match="round_spec_id_not_declared_in_case"):
        start_case_round(queue, case.case_id, "runtime-round-id")
    assert queue.db.execute(
        "SELECT COUNT(*) FROM queue WHERE research_case_id = ?", (case.case_id,)
    ).fetchone()[0] == 0


def test_planned_case_persists_separate_runtime_and_spec_ids(queue):
    case = planned_case()
    queue.register_research_case(case)
    result = start_case_round(queue, case.case_id, "source-pattern-v1")
    root = queue.db.execute(
        "SELECT round_id, round_spec_id FROM queue WHERE id = ?",
        (result["root_task_id"],),
    ).fetchone()
    registry = queue.db.execute(
        "SELECT round_id, round_spec_id, status, started_at, finished_at "
        "FROM research_case_rounds WHERE round_id = ?", (result["round_id"],)
    ).fetchone()
    assert result["round_id"] != "source-pattern-v1"
    assert result["round_spec_id"] == "source-pattern-v1"
    assert root == (result["round_id"], "source-pattern-v1")
    assert registry == (result["round_id"], "source-pattern-v1", "QUEUED", None, None)
