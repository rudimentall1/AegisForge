import json

from orchestrator.master import Master
from shared.queue import TaskQueue
from shared.research_case import ResearchCase, validate_worker_case_binding


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
    master = Master.__new__(Master)
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

    task_id = queue.add(
        description="Start the bounded forensic pipeline",
        role="source_researcher",
        research_case_id=case.case_id,
    )

    for role, result, expected_next_role in stages:
        row = queue.get(task_id)
        assert row is not None
        assert row[7] == role
        assert row[12] == case.case_id
        validate_worker_case_binding(role, queue.get_research_case(case.case_id), row[12])

        queue.finish(task_id, result=result)
        stored_result = queue.get_result(task_id)
        assert stored_result == result

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
        # A real worker loads this stored parent result before invoking its agent.
        assert queue.get_result(task_id) == result
        task_id = child_id
    else:
        raise AssertionError("The bounded pipeline did not reach a terminal validation decision")
