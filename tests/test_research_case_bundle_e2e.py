"""Synthetic end-to-end test for planned/runtime round identity in portable evidence."""

import json

from shared.case_rounds import start_case_round
from shared.evidence_ledger import EvidenceLedger
from shared.queue import TaskQueue
from shared.research_case import ResearchCase, RoundSpec, research_case_binding
from shared.research_case_bundle import (
    export_research_case_bundle,
    verify_research_case_bundle,
)
from shared.result_codec import encode


def _planned_case():
    return ResearchCase(
        case_id="bundle-e2e-planned-round",
        target_repository="example/protocol",
        target_commit="a" * 40,
        scope_url="https://example.com/security-scope",
        scope_digest="b" * 64,
        scope_reviewed_on="2026-10-16",
        hypothesis="A synthetic state transition may violate an invariant.",
        attacker_capability="A local deterministic test caller.",
        expected_invariant="The control state remains unchanged.",
        falsification_criteria="Reject the hypothesis if the counter-test preserves the invariant.",
        execution_mode="local",
        status="ready",
        allowed_techniques=("source_pattern",),
        rounds=(
            RoundSpec(
                round_id="synthetic-control-v1",
                technique="source_pattern",
                hypothesis="A synthetic state transition may violate an invariant.",
                expected_evidence_atoms=("source:synthetic-control",),
                falsification_criteria="Reject the hypothesis if the counter-test preserves the invariant.",
                disclosure_deadline_days=30,
            ),
        ),
    )


def test_planned_round_identity_survives_queue_evidence_export_and_offline_verify(tmp_path):
    db_path = tmp_path / "aegisforge-e2e.sqlite"
    bundle_path = tmp_path / "portable-case.zip"
    queue = TaskQueue(db_path=db_path)
    try:
        case = _planned_case()
        queue.register_research_case(case)

        started = start_case_round(queue, case.case_id, "synthetic-control-v1")
        root_id = started["root_task_id"]
        runtime_round_id = started["round_id"]
        planned_round_id = started["round_spec_id"]

        assert runtime_round_id != planned_round_id

        child_id = queue.add(
            "Synthetic local validation task",
            role="crypto_analyst",
            parent_task_id=root_id,
        )
        child = queue.db.execute(
            "SELECT research_case_id, round_id, round_spec_id FROM queue WHERE id = ?",
            (child_id,),
        ).fetchone()
        assert child == (case.case_id, runtime_round_id, planned_round_id)

        ledger = EvidenceLedger(queue.db)
        ledger.record_observation(
            child_id,
            "crypto_analyst",
            "source:synthetic-control",
        )
        observation = queue.db.execute(
            "SELECT case_id, round_id, round_spec_id FROM evidence_observations WHERE task_id = ?",
            (child_id,),
        ).fetchone()
        assert observation == (case.case_id, runtime_round_id, planned_round_id)

        result = {
            "stage": "validation",
            "research_case_binding": research_case_binding(case),
            "research_validation": {
                "historical_reproduction_confirmed": False,
                "conclusion": "INCONCLUSIVE",
                "synthetic_fixture": True,
            },
        }
        queue.db.execute(
            "UPDATE queue SET status = 'completed', result = ? WHERE id = ?",
            (encode(result), child_id),
        )
        queue.db.commit()

        export_report = export_research_case_bundle(
            db_path, case.case_id, bundle_path
        )
        verify_report = verify_research_case_bundle(bundle_path)

        assert export_report["valid"] is True
        assert verify_report == export_report

        import zipfile

        with zipfile.ZipFile(bundle_path, "r") as archive:
            tasks = json.loads(archive.read("tasks.json"))["tasks"]
            evidence = json.loads(archive.read("evidence.json"))["observations"]
            rounds = json.loads(archive.read("rounds.json"))

        root = next(task for task in tasks if task["id"] == root_id)
        child = next(task for task in tasks if task["id"] == child_id)
        assert root["round_id"] == runtime_round_id
        assert root["round_spec_id"] == planned_round_id
        assert child["round_id"] == runtime_round_id
        assert child["round_spec_id"] == planned_round_id
        assert evidence[0]["task_id"] == child_id
        assert evidence[0]["round_id"] == runtime_round_id
        assert evidence[0]["round_spec_id"] == planned_round_id
        assert rounds["registry_available"] is True
        assert rounds["rounds"][0]["round_id"] == runtime_round_id
        assert rounds["rounds"][0]["round_spec_id"] == planned_round_id
        assert result["research_validation"]["conclusion"] == "INCONCLUSIVE"
    finally:
        queue.db.close()
