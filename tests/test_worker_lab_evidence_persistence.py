"""Integration tests for the ordinary Worker -> LabRunner -> evidence path."""
import hashlib
from io import BytesIO
from types import SimpleNamespace
import zipfile

from agents.worker import Worker
from shared.capability_policy import ActionIntent, CapabilityDecision
from shared.case_rounds import start_case_round
from shared.evidence_ledger import EvidenceLedger
from shared.queue import TaskQueue
from shared.research_case import CaseStatus, ExecutionMode, ResearchCase, RoundSpec
from shared.local_experiment_bundle import (
    export_persisted_local_experiment_bundle,
    verify_local_experiment_bundle,
)
from shared.lab_experiment_persistence import persist_synthetic_lab_experiment


def _case_and_spec():
    spec = RoundSpec(
        round_id="lab-persistence-spec",
        technique="source_pattern",
        hypothesis="A built-in synthetic demo yields a portable integrity-checked record",
        expected_evidence_atoms=("synthetic_output",),
        falsification_criteria="The recorded output must match its raw artifact digest",
        priority=1,
        disclosure_deadline_days=30,
    )
    case = ResearchCase(
        case_id="lab-persistence-case",
        target_repository="example/project",
        target_commit="a" * 40,
        scope_url="https://github.com/example/project",
        scope_digest=hashlib.sha256(b"lab-persistence-scope").hexdigest(),
        scope_reviewed_on="2026-10-24",
        hypothesis=spec.hypothesis,
        attacker_capability="Repository-owned synthetic fixture only",
        expected_invariant="The experiment result is bound to its registered case",
        falsification_criteria=spec.falsification_criteria,
        execution_mode=ExecutionMode.LOCAL,
        status=CaseStatus.READY,
        allowed_techniques=("source_pattern",),
        rounds=(spec,),
    )
    return case, spec


def test_worker_lab_result_persists_and_exports_offline_bundle(tmp_path, capsys):
    from agents.lab_runner.agent import LabRunner
    from shared.local_experiment_bundle import main as bundle_cli_main

    case, spec = _case_and_spec()
    db_path = tmp_path / "worker-lab-evidence.sqlite3"
    queue = TaskQueue(db_path=db_path)
    try:
        queue.register_research_case(case)
        started = start_case_round(queue, case.case_id, spec.round_id)
        root_id = started["root_task_id"]
        # The root must finish before the lab worker can claim its child task.
        queue.claim("root-test-worker", role="source_researcher")
        queue.finish(root_id, result={"status": "INCONCLUSIVE"})
        task_id = queue.add(
            "Run built-in synthetic LabRunner experiment",
            role="lab_runner",
            parent_task_id=root_id,
        )
        worker = Worker.__new__(Worker)
        worker.role = "lab_runner"
        worker.worker_id = "lab-runner-integration-test"
        worker.agent_id = "lab-runner-test"
        worker.agent_identity = SimpleNamespace(
            to_dict=lambda: {"agent_id": "lab-runner-test"}
        )
        worker.queue = queue
        worker.memory = SimpleNamespace(save_task=lambda task: None)
        worker.agent = LabRunner()
        worker.policy = SimpleNamespace(required_evidence=lambda intent: [])
        worker._capability_decision = lambda task: (
            ActionIntent(role="lab_runner", action="research"),
            {"decision": CapabilityDecision.ALLOW, "reason": "test-only allow"},
        )
        worker._record_capability_decision = lambda *args: None
        worker._enqueue_execution_handoff = lambda *args: None

        # The real LabRunner subprocess executes its fixed repository-owned toy
        # script. The worker uses its ordinary run_once() claim/dispatch path.
        assert worker.run_once() is True
        rows = queue.db.execute(
            "SELECT id, status FROM queue WHERE role = 'lab_runner'"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0] == (task_id, "completed")
        ledger = EvidenceLedger(queue.db)
        result = queue.get_result(task_id)
        evidence = result.get("local_experiment_evidence")
        assert evidence["status"] == "PERSISTED"
        assert evidence["integrity_only"] is True
        assert evidence["authenticated_execution"] is False
        # Worker.run_once() may emit diagnostics; isolate the CLI JSON response.
        capsys.readouterr()
        bundle_path = tmp_path / "portable-experiment.zip"
        assert bundle_cli_main([
            "export", "--db", str(db_path),
            "--record-digest", evidence["record_digest"],
            "--output", str(bundle_path),
        ]) == 0
        export_report = __import__("json").loads(capsys.readouterr().out)
        assert export_report["status"] == "PASS"
        bundle = bundle_path.read_bytes()

        # The CLI verifier must work after the source database is closed.
        queue.db.close()
        assert bundle_cli_main(["verify", str(bundle_path)]) == 0
        report = __import__("json").loads(capsys.readouterr().out)
        assert report["status"] == "PASS"
        assert report["case_id"] == case.case_id
        assert report["round_spec_id"] == spec.round_id
        assert report["task_id"] == task_id
        assert report["authenticated_execution"] is False
        assert report["vulnerability_confirmed"] is False

        with zipfile.ZipFile(BytesIO(bundle), "r") as archive:
            members = {name: archive.read(name) for name in archive.namelist()}
        members["stdout.bin"] += b"tampered"
        tampered_buffer = BytesIO()
        with zipfile.ZipFile(tampered_buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in members.items():
                archive.writestr(name, data)
        tampered_path = tmp_path / "tampered-experiment.zip"
        tampered_path.write_bytes(tampered_buffer.getvalue())
        assert bundle_cli_main(["verify", str(tampered_path)]) == 2
        tampered_report = __import__("json").loads(capsys.readouterr().out)
        assert tampered_report["status"] == "FAIL"
    finally:
        queue.db.close()


def test_persistence_adapter_rejects_execution_output_digest_mismatch(tmp_path):
    from agents.lab_runner.agent import LabRunner
    from shared.research_case import research_case_binding

    case, spec = _case_and_spec()
    queue = TaskQueue(db_path=tmp_path / "worker-lab-tamper.sqlite3")
    try:
        queue.register_research_case(case)
        started = start_case_round(queue, case.case_id, spec.round_id)
        root_id = started["root_task_id"]
        queue.claim("root-test-worker", role="source_researcher")
        queue.finish(root_id, result={"status": "INCONCLUSIVE"})
        task_id = queue.add(
            "Synthetic result digest mismatch fixture",
            role="lab_runner",
            parent_task_id=root_id,
        )
        claim = queue.claim("lab-test-worker", role="lab_runner")
        assert claim[0] == task_id
        experiment = LabRunner.run_synthetic_entropy_demo(
            case_binding=research_case_binding(case)
        )
        experiment["execution_record"]["stdout"] += "tampered"
        result = {
            "research_track": "evm_key_forensics",
            "research_case_binding": research_case_binding(case),
            "lab_experiments": [experiment],
        }
        queue.finish(task_id, result=result)
        ledger = EvidenceLedger(queue.db)
        import pytest
        with pytest.raises(ValueError, match="stdout_digest_mismatch"):
            persist_synthetic_lab_experiment(
                queue=queue,
                ledger=ledger,
                task_id=task_id,
                role="lab_runner",
                research_case=case,
                round_spec=spec,
                result_value=result,
            )
    finally:
        queue.db.close()
