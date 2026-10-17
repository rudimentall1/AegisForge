import json

from orchestrator.master import AutonomousPlanner
from shared.queue import TaskQueue
from shared.case_rounds import start_case_round
from shared.evidence_ledger import EvidenceLedger
from shared.research_case import (
    ResearchCase,
    research_case_binding,
    verify_research_case_binding,
    validate_worker_case_binding,
)


def test_case_identity_follows_source_analysis_lab_and_validation_stages(tmp_path):
    case = ResearchCase(
        case_id="pipeline-case-001",
        target_repository="example/protocol",
        target_commit="a" * 40,
        scope_url="https://example.com/security-scope",
        scope_digest="b" * 64,
        scope_reviewed_on="2026-10-16",
        hypothesis="A public state transition may violate an accounting invariant.",
        attacker_capability="An unprivileged caller can invoke the public method.",
        expected_invariant="The recorded balance matches the independently calculated balance.",
        falsification_criteria="Counter-tests preserve the invariant for the tested transitions.",
        execution_mode="local",
        status="ready",
    )
    queue = TaskQueue(db_path=tmp_path / "queue.db")
    queue.register_research_case(case)

    # Exercise the same specialized decision function used by the Master,
    # without starting the autonomous service or making network requests.
    master = AutonomousPlanner.__new__(AutonomousPlanner)
    master.information_gain = lambda result: 0.7
    master.compact_context = lambda value: json.dumps(value, sort_keys=True, default=str)

    stages = [
        (
            "source_researcher",
            {
                "research_track": "evm_key_forensics",
                "stage": "sources",
                "source_search_rounds": 0,
                "sources": [{"source_id": "source-1", "source_url": "https://example.com/source"}],
            },
            "crypto_analyst",
        ),
        (
            "crypto_analyst",
            {
                "research_track": "evm_key_forensics",
                "stage": "analysis",
                "hypotheses": [{"hypothesis_id": "H-1", "status": "OPEN"}],
            },
            "lab_runner",
        ),
        (
            "lab_runner",
            {
                "research_track": "evm_key_forensics",
                "stage": "lab",
                "lab_summary": {
                    "historical_implementation_reproduced": False,
                    "real_private_keys_used": False,
                },
            },
            "validator",
        ),
        (
            "validator",
            {
                "research_track": "evm_key_forensics",
                "stage": "validation",
                "source_search_rounds": 3,
                "research_validation": {
                    "historical_reproduction_confirmed": False,
                    "next_actions": ["historical reproduction remains unproven"],
                },
            },
            None,
        ),
    ]

    round_result = start_case_round(queue, case.case_id)
    round_id = round_result["round_id"]
    task_id = round_result["root_task_id"]
    ledger = EvidenceLedger(queue.db)

    for role, result, expected_next_role in stages:
        claimed = queue.claim(f"test-worker-{role}", role=role)
        assert claimed is not None
        assert claimed[0] == task_id
        row = queue.get(task_id)
        assert row is not None
        assert row[7] == role
        assert row[12] == case.case_id
        stored_round = queue.db.execute(
            "SELECT round_id FROM queue WHERE id = ?", (task_id,)
        ).fetchone()
        assert stored_round == (round_id,)
        validate_worker_case_binding(role, queue.get_research_case(case.case_id), row[12])

        # Mirror the worker's result-boundary contract: every successful stage
        # carries the canonical case envelope into the persisted queue result.
        result = dict(result)
        result["research_case_binding"] = research_case_binding(case)
        queue.finish(task_id, result=result)
        stored_result = queue.get_result(task_id)
        assert stored_result == result
        verified_case = verify_research_case_binding(
            stored_result["research_case_binding"]
        )
        assert verified_case["target_commit"] == case.target_commit
        assert stored_result["research_case_binding"]["case_id"] == row[12]
        ledger.record_observation(
            task_id,
            role,
            f"pipeline_stage:{role}",
        )
        observation = queue.db.execute(
            "SELECT case_id, round_id FROM evidence_observations WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        assert observation == (case.case_id, round_id)

        decision = master._choose_next_raw(
            {"id": task_id, "role": role, "result": stored_result}
        )
        if expected_next_role is None:
            assert decision[0] == "COMPLETE"
            assert decision[1] is None
            break

        assert decision[1] == expected_next_role
        child_id = queue.add(
            description=decision[2],
            role=expected_next_role,
            parent_task_id=task_id,
        )
        child = queue.get(child_id)
        assert child is not None
        assert child[12] == case.case_id
        child_round = queue.db.execute(
            "SELECT round_id FROM queue WHERE id = ?", (child_id,)
        ).fetchone()
        assert child_round == (round_id,)
        # A real worker loads this stored parent result before invoking its agent.
        assert queue.get_result(task_id) == result
        task_id = child_id
    else:
        raise AssertionError("The bounded pipeline did not reach a terminal validation decision")



def test_case_round_identity_survives_failed_child_retry_and_evidence(tmp_path):
    case = ResearchCase(
        case_id="pipeline-retry-case-001",
        target_repository="example/protocol",
        target_commit="a" * 40,
        scope_url="https://example.com/security-scope",
        scope_digest="b" * 64,
        scope_reviewed_on="2026-10-16",
        hypothesis="A bounded local test may violate an accounting invariant.",
        attacker_capability="An unprivileged caller can invoke the local test harness.",
        expected_invariant="Recorded and independently calculated balances match.",
        falsification_criteria="The hypothesis is rejected if counter-tests preserve the invariant.",
        execution_mode="local",
        status="ready",
    )
    queue = TaskQueue(db_path=tmp_path / "retry-queue.db")
    queue.register_research_case(case)
    round_result = start_case_round(queue, case.case_id)
    round_id = round_result["round_id"]
    root_id = round_result["root_task_id"]

    # Complete the parent so the child is eligible for a retry under the queue contract.
    root = queue.claim("source-worker", role="source_researcher")
    assert root is not None and root[0] == root_id
    queue.finish(root_id, result={"research_case_binding": research_case_binding(case)})

    child_id = queue.add(
        "bounded crypto analysis",
        role="crypto_analyst",
        parent_task_id=root_id,
    )
    child = queue.claim("crypto-worker", role="crypto_analyst")
    assert child is not None and child[0] == child_id
    queue.fail(child_id, result={"failure_reason": "synthetic_retry_fixture"})

    assert queue.requeue_failed(child_id) is True
    assert queue.retry_count(child_id) == 1
    retry = queue.claim("crypto-worker-retry", role="crypto_analyst")
    assert retry is not None and retry[0] == child_id

    task_row = queue.get(child_id)
    assert task_row is not None
    assert task_row[12] == case.case_id
    assert queue.db.execute(
        "SELECT round_id FROM queue WHERE id = ?", (child_id,)
    ).fetchone() == (round_id,)
    validate_worker_case_binding("crypto_analyst", queue.get_research_case(case.case_id), task_row[12])

    final_result = {
        "stage": "analysis_retry",
        "research_case_binding": research_case_binding(case),
        "historical_vulnerability_reproduced": False,
    }
    queue.finish(child_id, result=final_result)
    assert queue.get_result(child_id) == final_result

    ledger = EvidenceLedger(queue.db)
    ledger.record_observation(child_id, "crypto_analyst", "retry_lineage_preserved")
    observation = queue.db.execute(
        "SELECT case_id, round_id, role FROM evidence_observations WHERE task_id = ?",
        (child_id,),
    ).fetchone()
    assert observation == (case.case_id, round_id, "crypto_analyst")
    queue.db.close()
