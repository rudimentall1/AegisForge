from orchestrator.master import AutonomousPlanner, MasterOrchestrator
from shared.queue import TaskQueue
from shared.research_case import ResearchCase, research_case_binding


def _case(case_id="master-focus-case"):
    return ResearchCase(
        case_id=case_id,
        target_repository="johguse/profanity",
        target_commit="0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6",
        scope_url="https://github.com/rudimentall1/AegisForge/blob/main/docs/research/evm-key-forensics/KNOWN_VULNERABILITY_BENCHMARK.md",
        scope_digest="a" * 64,
        scope_reviewed_on="2026-10-16",
        hypothesis="Check the pinned Profanity seed-construction pattern without claiming runtime exploitability.",
        attacker_capability="Offline source review only; no wallet or key material.",
        expected_invariant="Claims remain tied to immutable source and primary disclosure evidence.",
        falsification_criteria="Missing or contradictory source evidence remains inconclusive.",
        execution_mode="local",
        status="ready",
    )


def test_case_bound_forensics_route_precedes_generic_novelty_gate(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.db")
    case = _case()
    queue.register_research_case(case)
    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    planner.queue = queue
    planner._choose_next_raw = lambda task: (
        "CONTINUE", "crypto_analyst", "analyze pinned sources", "case route", 0.5
    )
    # If the generic gate ran first, this history/novelty setup would mark the
    # result complete before the dedicated EVM stage transition.
    planner.branch_history = lambda *args, **kwargs: [object(), object()]
    planner.novelty_against_history = lambda *args, **kwargs: (0.0, 0, 3)

    decision = planner.choose_next({
        "id": "bound-source-task",
        "role": "source_researcher",
        "result": {
            "research_track": "evm_key_forensics",
            "stage": "sources",
            "research_case_binding": research_case_binding(case),
        },
    })

    assert decision[0] == "CONTINUE"
    assert decision[1] == "crypto_analyst"
    queue.db.close()


def test_master_bootstraps_a_registered_case_instead_of_generic_research(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.db")
    case = _case()
    queue.register_research_case(case)
    master = MasterOrchestrator.__new__(MasterOrchestrator)
    master.queue = queue

    assert master.bootstrap() is True
    rows = queue.db.execute(
        "SELECT id, role, parent_task_id, research_case_id, description FROM queue"
    ).fetchall()
    assert len(rows) == 1
    task_id, role, parent_id, case_id, description = rows[0]
    assert role == "source_researcher"
    assert parent_id is None
    assert case_id == case.case_id
    assert case.target_commit in description
    assert "EVM Key Forensics" in description

    # A second idle tick must not create a duplicate root or fall back to a
    # generic market-research root for the same registered case.
    assert master.bootstrap() is False
    assert queue.db.execute("SELECT COUNT(*) FROM queue").fetchone()[0] == 1
    queue.db.close()


def test_master_rejects_unregistered_or_mismatched_case_binding(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.db")
    case = _case()
    queue.register_research_case(case)
    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    planner.queue = queue

    assert planner._is_bound_evm_forensics_task({
        "role": "source_researcher",
        "result": {
            "research_track": "evm_key_forensics",
            "stage": "sources",
            "research_case_binding": research_case_binding(case),
        },
    })

    forged = dict(research_case_binding(case))
    forged["case_digest"] = "f" * 64
    assert not planner._is_bound_evm_forensics_task({
        "role": "source_researcher",
        "result": {
            "research_track": "evm_key_forensics",
            "stage": "sources",
            "research_case_binding": forged,
        },
    })
    assert not planner._is_bound_evm_forensics_task({
        "role": "researcher",
        "result": {
            "research_track": "evm_key_forensics",
            "stage": "sources",
            "research_case_binding": research_case_binding(case),
        },
    })
    queue.db.close()


def test_master_bootstraps_case_even_with_legacy_planner_backlog(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.db")
    legacy_id = queue.add(
        description="Legacy generic discovery task",
        role="researcher",
    )
    assert queue.claim("legacy-worker", role="researcher") is not None
    queue.finish(legacy_id, result={"opportunities": [{"name": "legacy/example"}]})
    assert queue.has_planner_work()

    case = _case("case-over-legacy-backlog")
    queue.register_research_case(case)
    master = MasterOrchestrator.__new__(MasterOrchestrator)
    master.queue = queue

    assert master.bootstrap() is True
    row = queue.db.execute(
        "SELECT role, research_case_id FROM queue WHERE research_case_id = ?",
        (case.case_id,),
    ).fetchone()
    assert row == ("source_researcher", case.case_id)
    queue.db.close()
