"""End-to-end local-only evidence pipeline dogfooding.

This is explicitly a synthetic fixture: it exercises real case registration,
queue lifecycle, ledger binding, and portable bundle verification without
executing an untrusted command or claiming a real vulnerability reproduction.
"""
import hashlib
import json
import zipfile

from shared.evidence_ledger import EvidenceLedger
from shared.experiment_assessment import assess_local_experiment_pair
from shared.local_experiment import build_experiment_record
from shared.local_experiment_bundle import (
    export_persisted_local_experiment_bundle,
    verify_local_experiment_bundle,
)
from shared.queue import TaskQueue
from shared.research_case import (
    CaseStatus,
    ExecutionMode,
    ResearchCase,
    RoundSpec,
    research_case_binding,
)
from shared.research_case_bundle import (
    export_research_case_bundle,
    verify_research_case_bundle,
)


def _case():
    round_spec = RoundSpec(
        round_id="e2e-runtime-round-1",
        technique="source_pattern",
        hypothesis="A synthetic control preserves the declared invariant",
        expected_evidence_atoms=("control_output", "falsification_output"),
        falsification_criteria="The control must preserve the invariant; the counter-test must detect the synthetic violation",
        disclosure_deadline_days=30,
    )
    case = ResearchCase(
        case_id="e2e-synthetic-case-1",
        target_repository="example/protocol",
        target_commit="a" * 40,
        scope_url="https://github.com/example/protocol",
        scope_digest=hashlib.sha256(b"synthetic scope fixture").hexdigest(),
        scope_reviewed_on="2026-10-19",
        hypothesis=round_spec.hypothesis,
        attacker_capability="Synthetic fixture input only; no network or chain access",
        expected_invariant="Control preserves state; counter-test detects the seeded violation",
        falsification_criteria=round_spec.falsification_criteria,
        execution_mode=ExecutionMode.LOCAL,
        status=CaseStatus.READY,
        allowed_techniques=("source_pattern",),
        rounds=(round_spec,),
    )
    return case, round_spec


def test_synthetic_case_queue_ledger_bundle_offline_verification(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "aegisforge-e2e.sqlite3")
    try:
        case, round_spec = _case()
        queue.register_research_case(case)
        stored_case = queue.get_research_case(case.case_id)
        assert stored_case is not None
        assert stored_case.target_commit == case.target_commit

        ledger = EvidenceLedger(queue.db)
        task_id = queue.add(
            "Synthetic local control experiment",
            role="lab_runner",
            research_case_id=case.case_id,
            round_id=round_spec.round_id,
        )
        claimed = queue.claim("e2e-worker-1", role="lab_runner")
        assert claimed is not None
        assert claimed[0] == task_id
        assert claimed[12] == case.case_id
        assert queue.db.execute(
            "SELECT round_id FROM queue WHERE id = ?", (task_id,)
        ).fetchone()[0] == round_spec.round_id

        control_output = b"SYNTHETIC_FIXTURE control=PASS invariant_preserved=true\n"
        queue.finish(task_id, result={
            "synthetic_fixture": True,
            "experiment": "control",
            "invariant_preserved": True,
            "research_case_binding": research_case_binding(case),
        })
        record, artifacts = build_experiment_record(
            case_id=case.case_id,
            round_id=round_spec.round_id,
            task_id=task_id,
            target_repository=case.target_repository,
            target_commit=case.target_commit,
            argv=["synthetic-fixture", "control"],
            toolchain={"python": "CI runtime", "fixture": "aegisforge-e2e-v1"},
            input_bytes=b"synthetic control input",
            stdout_bytes=control_output,
            stderr_bytes=b"",
            exit_code=0,
        )
        stored = ledger.record_local_experiment(record, artifacts)
        bundle = export_persisted_local_experiment_bundle(
            ledger, stored["record_digest"]
        )
        report = verify_local_experiment_bundle(bundle)
        assert report["status"] == "PASS"
        assert report["case_id"] == case.case_id
        assert report["round_id"] == round_spec.round_id
        assert report["task_id"] == task_id
        assert report["experiment_status"] == "PASS"
        assert report["integrity_only"] is True
        assert report["authenticated_execution"] is False
        assert report["execution_provenance"]["status"] == "UNAUTHENTICATED"
        assert report["execution_provenance"]["execution_claim_source"] == "BUNDLE_METADATA"
        assert report["vulnerability_confirmed"] is False

        # The counter-test is represented as a separate terminal task and
        # evidence record. It detects a deliberately seeded synthetic violation;
        # it is not evidence of a real target vulnerability.
        counter_task_id = queue.add(
            "Synthetic falsification counter-test",
            role="lab_runner",
            research_case_id=case.case_id,
            round_id=round_spec.round_id,
        )
        counter_claim = queue.claim("e2e-worker-2", role="lab_runner")
        assert counter_claim is not None
        assert counter_claim[0] == counter_task_id
        counter_output = (
            b"SYNTHETIC_FIXTURE counter_test=PASS "
            b"seeded_violation_detected=true\n"
        )
        queue.finish(counter_task_id, result={
            "synthetic_fixture": True,
            "experiment": "falsification_counter_test",
            "seeded_violation_detected": True,
            "research_case_binding": research_case_binding(case),
        })
        counter_record, counter_artifacts = build_experiment_record(
            case_id=case.case_id,
            round_id=round_spec.round_id,
            task_id=counter_task_id,
            target_repository=case.target_repository,
            target_commit=case.target_commit,
            argv=["synthetic-fixture", "falsification-counter-test"],
            toolchain={"python": "CI runtime", "fixture": "aegisforge-e2e-v1"},
            input_bytes=b"synthetic seeded-violation input",
            stdout_bytes=counter_output,
            stderr_bytes=b"",
            exit_code=0,
        )
        counter_stored = ledger.record_local_experiment(
            counter_record, counter_artifacts
        )
        counter_bundle = export_persisted_local_experiment_bundle(
            ledger, counter_stored["record_digest"]
        )
        counter_report = verify_local_experiment_bundle(counter_bundle)
        assert counter_report["status"] == "PASS"
        assert counter_report["case_id"] == case.case_id
        assert counter_report["round_id"] == round_spec.round_id
        assert counter_report["task_id"] == counter_task_id
        assert counter_report["experiment_status"] == "PASS"
        assert counter_report["vulnerability_confirmed"] is False

        assessment = assess_local_experiment_pair(
            control_bundle=bundle,
            countertest_bundle=counter_bundle,
            expected_case_id=case.case_id,
            expected_round_id=round_spec.round_id,
            expected_target_repository=case.target_repository,
            expected_target_commit=case.target_commit,
            semantic_criteria={
                "case_id": case.case_id,
                "round_id": round_spec.round_id,
                "target_repository": case.target_repository,
                "target_commit": case.target_commit,
                "invariant": case.expected_invariant,
                "falsification_criteria": case.falsification_criteria,
                "control": {
                    "must_contain": ["invariant_preserved=true"],
                    "must_not_contain": ["invariant_preserved=false"],
                },
                "countertest": {
                    "must_contain": ["seeded_violation_detected=true"],
                    "must_not_contain": ["seeded_violation_detected=false"],
                },
            },
            synthetic_fixture=True,
        )
        assert assessment["status"] == "INCONCLUSIVE"
        assert assessment["vulnerability_status"] == "INCONCLUSIVE"
        assert assessment["vulnerability_confirmed"] is False
        assert assessment["checks"]["identity_match"] is True
        assert counter_task_id != task_id

        # Independently export the registered Research Case dossier from the
        # same queue database. The portable case dossier must retain both task
        # identities that anchor the two local-experiment records.
        dossier_path = tmp_path / "e2e-research-case.zip"
        dossier_report = export_research_case_bundle(
            tmp_path / "aegisforge-e2e.sqlite3",
            case.case_id,
            dossier_path,
        )
        offline_dossier_report = verify_research_case_bundle(dossier_path)
        assert dossier_report["valid"] is True
        assert offline_dossier_report["valid"] is True
        assert offline_dossier_report["case_id"] == case.case_id
        assert offline_dossier_report["task_count"] == 2
        assert offline_dossier_report["authenticity"] == "UNSIGNED_INTEGRITY_ONLY"
        with zipfile.ZipFile(dossier_path, "r") as dossier:
            tasks_payload = json.loads(dossier.read("tasks.json"))
        exported_task_ids = {task["id"] for task in tasks_payload["tasks"]}
        assert exported_task_ids == {task_id, counter_task_id}
    finally:
        queue.db.close()
