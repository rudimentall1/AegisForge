"""End-to-end local-only evidence pipeline dogfooding.

This is explicitly a synthetic fixture: it exercises real case registration,
queue lifecycle, ledger binding, and portable bundle verification without
executing an untrusted command or claiming a real vulnerability reproduction.
"""
import hashlib
import io
import json
import zipfile

import pytest

from shared.case_rounds import start_case_round
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
from shared.research_case_evidence_package import (
    build_research_case_evidence_package,
    main as research_case_evidence_package_main,
    verify_research_case_evidence_package,
)
from shared.synthetic_fixture import run_synthetic_fixture


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
        # Pin the repository commit that introduced this fixture implementation.
        # The tested behavior is synthetic harness behavior, not a target finding.
        target_repository="rudimentall1/AegisForge",
        target_commit="cd3d185e56b7fdf4c024a5e7f8ae20d021675e70",
        scope_url="https://github.com/rudimentall1/AegisForge",
        scope_digest=hashlib.sha256(
            b"synthetic fixture scope: shared/synthetic_fixture.py@"
            b"cd3d185e56b7fdf4c024a5e7f8ae20d021675e70"
        ).hexdigest(),
        scope_reviewed_on="2026-10-22",
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
        started_round = start_case_round(queue, case.case_id, round_spec.round_id)
        root_task_id = started_round["root_task_id"]
        runtime_round_id = started_round["round_id"]
        planned_round_id = started_round["round_spec_id"]
        assert runtime_round_id != planned_round_id == round_spec.round_id

        root_claim = queue.claim("e2e-root-worker", role="source_researcher")
        assert root_claim is not None
        assert root_claim[0] == root_task_id

        # Queue both experiment tasks while the root is running, so the registry
        # cannot transiently mark the runtime round complete between the pair.
        task_id = queue.add(
            "Synthetic local control experiment",
            role="lab_runner",
            parent_task_id=root_task_id,
            research_case_id=case.case_id,
            round_id=runtime_round_id,
            round_spec_id=planned_round_id,
        )
        counter_task_id = queue.add(
            "Synthetic falsification counter-test",
            role="lab_runner",
            parent_task_id=root_task_id,
            research_case_id=case.case_id,
            round_id=runtime_round_id,
            round_spec_id=planned_round_id,
        )
        for child_id in (task_id, counter_task_id):
            child_identity = queue.db.execute(
                "SELECT research_case_id, round_id, round_spec_id FROM queue WHERE id = ?",
                (child_id,),
            ).fetchone()
            assert child_identity == (case.case_id, runtime_round_id, planned_round_id)

        queue.finish(root_task_id, result={
            "synthetic_fixture": True,
            "round_dispatch": "INCONCLUSIVE",
            "research_case_binding": research_case_binding(case),
        })
        claimed = queue.claim("e2e-worker-1", role="lab_runner")
        assert claimed is not None
        assert claimed[0] == task_id

        control_fixture = run_synthetic_fixture("control")
        assert control_fixture["passed"] is True
        assert control_fixture["subprocess_started"] is False
        assert control_fixture["network_access"] is False
        control_output = control_fixture["stdout_bytes"]
        queue.finish(task_id, result={
            "synthetic_fixture": True,
            "experiment": "control",
            "invariant_preserved": control_fixture["checks"]["invariant_preserved"],
            "research_case_binding": research_case_binding(case),
        })
        record, artifacts = build_experiment_record(
            case_id=case.case_id,
            round_id=runtime_round_id,
            round_spec_id=planned_round_id,
            task_id=task_id,
            target_repository=case.target_repository,
            target_commit=case.target_commit,
            argv=control_fixture["argv"],
            toolchain=control_fixture["toolchain"],
            input_bytes=control_fixture["input_bytes"],
            stdout_bytes=control_output,
            stderr_bytes=control_fixture["stderr_bytes"],
            exit_code=control_fixture["exit_code"],
            expected_exit_code=control_fixture["expected_exit_code"],
        )
        stored = ledger.record_local_experiment(record, artifacts)
        ledger.record_observation(
            task_id,
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
        counter_claim = queue.claim("e2e-worker-2", role="lab_runner")
        assert counter_claim is not None
        assert counter_claim[0] == counter_task_id
        counter_fixture = run_synthetic_fixture("countertest")
        assert counter_fixture["passed"] is True
        assert counter_fixture["subprocess_started"] is False
        assert counter_fixture["network_access"] is False
        counter_output = counter_fixture["stdout_bytes"]
        queue.finish(counter_task_id, result={
            "synthetic_fixture": True,
            "experiment": "falsification_counter_test",
            "seeded_violation_detected": counter_fixture["checks"]["seeded_violation_detected"],
            "research_case_binding": research_case_binding(case),
        })
        counter_record, counter_artifacts = build_experiment_record(
            case_id=case.case_id,
            round_id=runtime_round_id,
            round_spec_id=planned_round_id,
            task_id=counter_task_id,
            target_repository=case.target_repository,
            target_commit=case.target_commit,
            argv=counter_fixture["argv"],
            toolchain=counter_fixture["toolchain"],
            input_bytes=counter_fixture["input_bytes"],
            stdout_bytes=counter_output,
            stderr_bytes=counter_fixture["stderr_bytes"],
            exit_code=counter_fixture["exit_code"],
            expected_exit_code=counter_fixture["expected_exit_code"],
        )
        counter_stored = ledger.record_local_experiment(
            counter_record, counter_artifacts
        )
        ledger.record_observation(
            counter_task_id,
            "lab_runner",
            f"local_experiment_record:{counter_stored['record_digest']}",
        )
        counter_bundle = export_persisted_local_experiment_bundle(
            ledger, counter_stored["record_digest"]
        )
        counter_report = verify_local_experiment_bundle(counter_bundle)
        assert counter_report["status"] == "PASS"
        assert counter_report["case_id"] == case.case_id
        assert counter_report["round_id"] == runtime_round_id
        assert counter_report["round_spec_id"] == planned_round_id
        assert counter_report["task_id"] == counter_task_id
        assert counter_report["experiment_status"] == "PASS"
        assert counter_report["vulnerability_confirmed"] is False

        assessment = assess_local_experiment_pair(
            control_bundle=bundle,
            countertest_bundle=counter_bundle,
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
        assert offline_dossier_report["task_count"] == 3
        assert offline_dossier_report["authenticity"] == "UNSIGNED_INTEGRITY_ONLY"
        with zipfile.ZipFile(dossier_path, "r") as dossier:
            tasks_payload = json.loads(dossier.read("tasks.json"))
            evidence_payload = json.loads(dossier.read("evidence.json"))
            rounds_payload = json.loads(dossier.read("rounds.json"))
        exported_task_ids = {task["id"] for task in tasks_payload["tasks"]}
        assert exported_task_ids == {root_task_id, task_id, counter_task_id}

        evidence_by_task = {
            item["task_id"]: item for item in evidence_payload["observations"]
        }
        assert set(evidence_by_task) == {task_id, counter_task_id}
        assert len(evidence_by_task) == 2
        for evidence in evidence_by_task.values():
            assert evidence["case_id"] == case.case_id
            assert evidence["round_id"] == runtime_round_id
            assert evidence["round_spec_id"] == planned_round_id
            assert evidence["role"] == "lab_runner"
            assert evidence["atom_id"] in {
                ledger.atom_id(f"local_experiment_record:{stored['record_digest']}"),
                ledger.atom_id(
                    f"local_experiment_record:{counter_stored['record_digest']}"
                ),
            }

        registry_rounds = rounds_payload["rounds"]
        assert rounds_payload["registry_available"] is True
        assert len(registry_rounds) == 1
        registry_round = registry_rounds[0]
        assert registry_round["case_id"] == case.case_id
        assert registry_round["round_id"] == runtime_round_id
        assert registry_round["round_id"] != registry_round["round_spec_id"]
        assert registry_round["round_spec_id"] == planned_round_id
        assert registry_round["root_task_id"] == root_task_id
        assert registry_round["status"] == "COMPLETED"
        assert registry_round["started_at"] is not None
        assert registry_round["finished_at"] is not None

        # Build and verify the combined package through the public offline CLI.
        control_bundle_path = tmp_path / "control-experiment.zip"
        counter_bundle_path = tmp_path / "counter-experiment.zip"
        package_path = tmp_path / "case-evidence-package.zip"
        control_bundle_path.write_bytes(bundle)
        counter_bundle_path.write_bytes(counter_bundle)
        build_exit = research_case_evidence_package_main([
            "build",
            "--case-dossier", str(dossier_path),
            "--experiment", str(control_bundle_path),
            "--experiment", str(counter_bundle_path),
            "--output", str(package_path),
        ])
        assert build_exit == 0
        package_bytes = package_path.read_bytes()
        package_report = verify_research_case_evidence_package(package_bytes)
        assert research_case_evidence_package_main([
            "verify", str(package_path)
        ]) == 0
        assert package_report["status"] == "PASS"
        assert package_report["case_id"] == case.case_id
        assert package_report["case_digest"] == dossier_report["case_digest"]
        assert package_report["experiment_count"] == 2
        assert set(package_report["task_ids"]) == {task_id, counter_task_id}
        assert set(package_report["record_digests"]) == {
            stored["record_digest"], counter_stored["record_digest"]
        }
        assert package_report["round_ids"] == [runtime_round_id]
        assert package_report["round_spec_ids"] == [planned_round_id]
        assert package_report["authenticity"] == "UNSIGNED_INTEGRITY_ONLY"
        assert package_report["vulnerability_confirmed"] is False

        changed_package = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(package_bytes), "r") as source:
            with zipfile.ZipFile(
                changed_package, "w", compression=zipfile.ZIP_DEFLATED
            ) as output:
                for info in source.infolist():
                    raw = source.read(info.filename)
                    if info.filename == "experiments/0000.zip":
                        raw += b"tampered"
                    output.writestr(info.filename, raw)
        tamper_report = verify_research_case_evidence_package(
            changed_package.getvalue()
        )
        assert tamper_report["status"] == "FAIL"
        assert tamper_report["errors"] == ["package_member_digest_mismatch"]

        with pytest.raises(
            ValueError,
            match="package_experiment_set_does_not_match_dossier_evidence",
        ):
            build_research_case_evidence_package(
                dossier_path.read_bytes(),
                [bundle],
            )
    finally:
        queue.db.close()
