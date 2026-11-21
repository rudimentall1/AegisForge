import hashlib
from types import SimpleNamespace

import shared.queue as queue_module
from agents.lab_runner.agent import LabRunner
from agents.worker import Worker
from shared.case_rounds import start_case_round
from shared.capability_policy import CapabilityPolicy
from shared.evidence_ledger import EvidenceLedger
from shared.queue import TaskQueue
from shared.research_case import ExecutionMode, ResearchCase, RoundSpec


def test_worker_dispatches_planned_foundry_round_and_persists_evidence(
    monkeypatch, tmp_path, capsys
):
    import agents.worker as worker_module

    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "worker-foundry.db")
    monkeypatch.setenv("AEGISFORGE_TARGET_CHECKOUT_ROOT", str(tmp_path / "target"))
    monkeypatch.setenv("AEGISFORGE_DOCKER_RUNTIME_AUTHORIZED", "1")
    spec = RoundSpec(
        round_id="worker-foundry-spec",
        technique="runtime_probe",
        hypothesis="A reentrant callback can withdraw credit more than once.",
        expected_evidence_atoms=("positive_control", "negative_control"),
        falsification_criteria="A safe control rejects the repeated withdrawal.",
        target_source_paths=("src/Vault.sol",),
        test_harness_source=(
            "contract Harness { "
            "function testPositiveControl() public pure { require(true); } "
            "function testNegativeControl() public pure { require(true); } "
            "}"
        ),
        solc_version="0.8.24",
        foundry_image="ghcr.io/foundry-rs/foundry@sha256:" + ("d" * 64),
        positive_control_test="testPositiveControl",
        negative_control_test="testNegativeControl",
        priority=1,
        disclosure_deadline_days=30,
    )
    case = ResearchCase(
        case_id="worker-foundry-case",
        target_repository="acme/vault",
        target_commit="a" * 40,
        scope_url="https://example.com/scope",
        scope_digest=hashlib.sha256(b"scope").hexdigest(),
        scope_reviewed_on="2026-11-01",
        hypothesis=spec.hypothesis,
        attacker_capability="Networkless local Foundry harness",
        expected_invariant="A credit cannot be consumed twice.",
        falsification_criteria=spec.falsification_criteria,
        execution_mode=ExecutionMode.LOCAL,
        allowed_techniques=("runtime_probe",),
        rounds=(spec,),
    )
    queue = TaskQueue()
    try:
        queue.register_research_case(case)
        started = start_case_round(queue, case.case_id, spec.round_id)
        queue.claim("root-worker", role="source_researcher")
        queue.finish(started["root_task_id"], result={"status": "INCONCLUSIVE"})
        task_id = queue.add(
            "Execute planned Foundry exploit harness",
            role="lab_runner",
            parent_task_id=started["root_task_id"],
        )

        stdout = "forge test: 1 passed\n"
        stderr = ""
        def fake_foundry(queue_arg, request, *, checkout_root):
            assert queue_arg is queue
            assert request.task_id == task_id
            assert request.adapter_profile.value == "foundry_test"
            assert checkout_root == str(tmp_path / "target")
            return {
                "execution_adapter": "foundry_test",
                "research_track": "foundry_runtime_probe",
                "case_id": case.case_id,
                "round_id": started["round_id"],
                "round_spec_id": spec.round_id,
                "target_commit": case.target_commit,
                "source_provenance": "git_object_database_at_verified_commit",
                "pinned_source_tree_sha256": "b" * 64,
                "source_sha256": {"src/Vault.sol": "c" * 64},
                "test_harness_sha256": hashlib.sha256(
                    spec.test_harness_source.encode()
                ).hexdigest(),
                "compiler_version": spec.solc_version,
                "status": "EXECUTED_PASS",
                "execution_truth": "LOCAL_CONTAINER_OBSERVATION_ONLY",
                "network_access": False,
                "host_filesystem_access": False,
                "project_mount_read_only": True,
                "transactions_sent": False,
                "test_statuses": {
                    "testPositiveControl": "Success",
                    "testNegativeControl": "Success",
                },
                "test_counts": {"total": 2, "passed": 2, "failed": 0, "skipped": 0},
                "control_tests": {
                    "positive": {"name": "testPositiveControl", "status": "Success"},
                    "negative": {"name": "testNegativeControl", "status": "Success"},
                },
                "exit_code": 0,
                "command": ["forge", "test", "--offline"],
                "stdout": stdout,
                "stderr": stderr,
                "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
                "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
                "container_image": "ghcr.io/foundry-rs/foundry@sha256:" + ("d" * 64),
                "foundry_source_root": spec.foundry_source_root,
                "dynamic_verified": False,
                "confirmed": False,
                "vulnerability_confirmed": False,
            }

        monkeypatch.setattr(worker_module, "run_admitted_foundry_round", fake_foundry)
        worker = Worker.__new__(Worker)
        worker.role = "lab_runner"
        worker.worker_id = "foundry-worker-test"
        worker.agent_id = "foundry-worker-agent"
        worker.agent_identity = SimpleNamespace(
            to_dict=lambda: {"agent_id": "foundry-worker-agent"}
        )
        worker.queue = queue
        worker.memory = SimpleNamespace(save_task=lambda task: None)
        worker.agent = LabRunner()
        worker.evidence_ledger = EvidenceLedger(queue.db)
        worker.policy = CapabilityPolicy()
        worker._record_capability_decision = lambda *args: None
        worker._enqueue_execution_handoff = lambda *args: None

        assert worker.run_once() is True
        result = queue.get_result(task_id)
        assert result["execution_adapter"] == "foundry_test"
        assert result["status"] == "EXECUTED_PASS"
        assert result["local_experiment_evidence"]["status"] == "PERSISTED"
        assert result["local_experiment_evidence"]["vulnerability_confirmed"] is False
        assert "stdout" not in result
        assert "stderr" not in result
        count = queue.db.execute(
            "SELECT COUNT(*) FROM local_experiment_records WHERE task_id = ?",
            (task_id,),
        ).fetchone()[0]
        assert count == 1
        capsys.readouterr()
    finally:
        queue.db.close()
