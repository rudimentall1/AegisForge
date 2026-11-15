"""Bubblewrap-isolated fixture results must enter the existing evidence model.

This test is skipped on hosts without Bubblewrap. CI installs Bubblewrap, so the
release pipeline exercises the isolated backend and verifies persisted bundles.
It remains a synthetic harness test, not target-code execution.
"""
import hashlib
import shutil

import pytest

from shared.case_rounds import start_case_round
from shared.evidence_ledger import EvidenceLedger
from shared.experiment_assessment import assess_local_experiment_pair
from shared.isolated_synthetic_fixture_runner import run_isolated_synthetic_fixture
from shared.local_experiment import build_experiment_record
from shared.local_experiment_bundle import (
    export_persisted_local_experiment_bundle,
    verify_local_experiment_bundle,
)
from shared.research_case_bundle import (
    export_research_case_bundle,
    verify_research_case_bundle,
)
from shared.research_case_evidence_package import (
    build_research_case_evidence_package,
    verify_research_case_evidence_package,
)
from shared.queue import TaskQueue
from shared.research_case import (
    CaseStatus,
    ExecutionMode,
    ResearchCase,
    RoundSpec,
    research_case_binding,
)


def test_bubblewrap_fixture_results_persist_and_verify_end_to_end(tmp_path):
    if not shutil.which("bwrap"):
        pytest.skip("Bubblewrap is not installed; isolated backend is fail-closed")

    spec = RoundSpec(
        round_id="bwrap-planned-round",
        technique="source_pattern",
        hypothesis="The isolated synthetic control preserves its invariant",
        expected_evidence_atoms=("control_output", "countertest_output"),
        falsification_criteria="The isolated counter-test detects the seeded synthetic violation",
        disclosure_deadline_days=30,
    )
    case = ResearchCase(
        case_id="bwrap-evidence-case",
        target_repository="rudimentall1/AegisForge",
        target_commit="97e3f751bde363f8ad442101e6ce4168ae5e9c0a",
        scope_url="https://github.com/rudimentall1/AegisForge",
        scope_digest=hashlib.sha256(
            b"Bubblewrap fixed-fixture acceptance scope v1"
        ).hexdigest(),
        scope_reviewed_on="2026-11-14",
        hypothesis=spec.hypothesis,
        attacker_capability="Fixed repository-owned synthetic fixture only",
        expected_invariant="Control preserves state; counter-test detects seeded violation",
        falsification_criteria=spec.falsification_criteria,
        execution_mode=ExecutionMode.LOCAL,
        status=CaseStatus.READY,
        allowed_techniques=("source_pattern",),
        rounds=(spec,),
    )

    db_path = tmp_path / "bwrap-evidence.sqlite3"
    queue = TaskQueue(db_path=db_path)
    try:
        queue.register_research_case(case)
        ledger = EvidenceLedger(queue.db)
        round_info = start_case_round(queue, case.case_id, spec.round_id)
        root_id = round_info["root_task_id"]
        runtime_round_id = round_info["round_id"]
        planned_round_id = round_info["round_spec_id"]

        root_claim = queue.claim("bwrap-root-worker", role="source_researcher")
        assert root_claim is not None and root_claim[0] == root_id

        task_ids = {}
        for mode in ("control", "countertest"):
            task_ids[mode] = queue.add(
                f"Bubblewrap isolated {mode}",
                role="lab_runner",
                parent_task_id=root_id,
                research_case_id=case.case_id,
                round_id=runtime_round_id,
                round_spec_id=planned_round_id,
            )

        queue.finish(root_id, result={
            "research_case_binding": research_case_binding(case),
            "round_dispatch": "INCONCLUSIVE",
        })

        bundles = {}
        reports = {}
        records = {}
        for mode in ("control", "countertest"):
            claimed = queue.claim(f"bwrap-{mode}-worker", role="lab_runner")
            assert claimed is not None and claimed[0] == task_ids[mode]

            execution = run_isolated_synthetic_fixture(mode)
            assert execution["execution"]["status"] == "PASS"
            assert execution["execution"]["network_isolation_enforced"] is True
            assert execution["execution"]["filesystem_isolation_enforced"] is True
            assert execution["execution"]["network_namespace_checked"] is True
            assert execution["execution"]["read_only_system_tree_checked"] is True
            assert execution["execution"]["private_tmp_write_checked"] is True
            assert execution["execution_mode"] == "bubblewrap_isolated_fixed_fixture"

            queue.finish(task_ids[mode], result={
                "research_case_binding": research_case_binding(case),
                "synthetic_fixture": True,
                "mode": mode,
                "execution_status": "PASS",
            })
            record, artifacts = build_experiment_record(
                case_id=case.case_id,
                round_id=runtime_round_id,
                round_spec_id=planned_round_id,
                task_id=task_ids[mode],
                target_repository=case.target_repository,
                target_commit=case.target_commit,
                argv=execution["argv"],
                toolchain=execution["toolchain"],
                input_bytes=execution["input_bytes"],
                stdout_bytes=execution["stdout_bytes"],
                stderr_bytes=execution["stderr_bytes"],
                exit_code=execution["exit_code"],
                expected_exit_code=0,
            )
            stored = ledger.record_local_experiment(record, artifacts)
            ledger.record_observation(
                task_ids[mode],
                "lab_runner",
                f"local_experiment_record:{stored['record_digest']}",
            )
            bundle = export_persisted_local_experiment_bundle(
                ledger, stored["record_digest"]
            )
            report = verify_local_experiment_bundle(bundle)
            assert report["status"] == "PASS"
            assert report["case_id"] == case.case_id
            assert report["round_id"] == runtime_round_id
            assert report["round_spec_id"] == planned_round_id
            assert report["task_id"] == task_ids[mode]
            assert report["experiment_status"] == "PASS"
            assert report["vulnerability_confirmed"] is False
            bundles[mode] = bundle
            reports[mode] = report
            records[mode] = record

        assessment = assess_local_experiment_pair(
            control_bundle=bundles["control"],
            countertest_bundle=bundles["countertest"],
            expected_case_id=case.case_id,
            expected_round_id=runtime_round_id,
            expected_round_spec_id=planned_round_id,
            expected_target_repository=case.target_repository,
            expected_target_commit=case.target_commit,
            semantic_criteria={
                "case_id": case.case_id,
                "round_id": runtime_round_id,
                "round_spec_id": planned_round_id,
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
        assert task_ids["control"] != task_ids["countertest"]

        # Carry the actual isolated control/counter-test records through the
        # Research Case dossier and independently verifiable outer package.
        dossier_path = tmp_path / "bwrap-case-dossier.zip"
        dossier_export = export_research_case_bundle(
            db_path, case.case_id, dossier_path
        )
        assert dossier_export["valid"] is True
        dossier_report = verify_research_case_bundle(dossier_path)
        assert dossier_report["valid"] is True
        assert dossier_report["case_id"] == case.case_id
        assert dossier_report["case_digest"]

        package = build_research_case_evidence_package(
            dossier_path.read_bytes(),
            [bundles["control"], bundles["countertest"]],
        )
        package_report = verify_research_case_evidence_package(package)
        assert package_report["status"] == "PASS"
        assert package_report["package_integrity_status"] == "PASS"
        assert package_report["case_id"] == case.case_id
        assert package_report["experiment_count"] == 2
        assert set(package_report["task_ids"]) == set(task_ids.values())
        assert package_report["round_ids"] == [runtime_round_id]
        assert package_report["round_spec_ids"] == [planned_round_id]
        assert package_report["attestation_verification_status"] == "NOT_PRESENT"
        assert package_report["attestation_coverage_status"] == "NOT_PRESENT"
        assert package_report["authenticity"] == "UNSIGNED_INTEGRITY_ONLY"
        assert package_report["execution_truth_established"] is False
        assert package_report["vulnerability_confirmed"] is False
    finally:
        queue.db.close()
