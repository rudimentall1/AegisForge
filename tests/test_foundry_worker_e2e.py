import hashlib
import os
import shutil
import subprocess
from datetime import date
from pathlib import Path
from types import SimpleNamespace

import pytest

import shared.queue as queue_module
from agents.lab_runner.agent import LabRunner
from agents.worker import Worker
from shared.capability_policy import CapabilityPolicy
from shared.case_rounds import start_case_round
from shared.evidence_ledger import EvidenceLedger
from shared.queue import TaskQueue
from shared.research_case import ExecutionMode, ResearchCase, RoundSpec


pytestmark = pytest.mark.skipif(
    os.getenv("AEGISFORGE_FOUNDRY_WORKER_E2E") != "1",
    reason="set AEGISFORGE_FOUNDRY_WORKER_E2E=1 on a configured dedicated Docker runner",
)


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *args],
        text=True,
        stderr=subprocess.PIPE,
    ).strip()


def test_worker_executes_real_reentrancy_benchmark_and_persists_evidence(
    monkeypatch, tmp_path
):
    image = os.getenv("AEGISFORGE_FOUNDRY_E2E_IMAGE", "")
    compiler = os.getenv("AEGISFORGE_SOLC_BINARY", "")
    assert image.startswith("ghcr.io/foundry-rs/foundry@sha256:")
    assert len(image.rsplit(":", 1)[-1]) == 64
    assert compiler and Path(compiler).is_file() and os.access(compiler, os.X_OK)
    assert shutil.which("docker"), "Docker CLI is required for opt-in worker E2E"

    repository_root = tmp_path / "target"
    repository_root.mkdir()
    subprocess.run(["git", "init", str(repository_root)], check=True, capture_output=True)
    _git(repository_root, "config", "user.email", "e2e@example.invalid")
    _git(repository_root, "config", "user.name", "AegisForge E2E")
    (repository_root / "src").mkdir()
    (repository_root / "src" / "ReentrancyVault.sol").write_text(
        Path("benchmark/src/ReentrancyVault.sol").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    subprocess.run(
        ["git", "-C", str(repository_root), "add", "src/ReentrancyVault.sol"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository_root), "commit", "-m", "pinned reentrancy target"],
        check=True,
        capture_output=True,
    )
    target_commit = _git(repository_root, "rev-parse", "HEAD")
    _git(
        repository_root,
        "remote",
        "add",
        "origin",
        "https://github.com/acme/reentrancy-vault.git",
    )

    harness = Path("benchmark/test/ReentrancyBenchmark.t.sol").read_text(
        encoding="utf-8"
    )
    spec = RoundSpec(
        round_id="worker-e2e-reentrancy",
        technique="runtime_probe",
        hypothesis="A reentrant callback can withdraw a vulnerable vault credit more than once.",
        expected_evidence_atoms=("positive_control", "negative_control"),
        falsification_criteria="The safe control retains victim funds under the same callback attack.",
        target_source_paths=("src/ReentrancyVault.sol",),
        foundry_source_root="src",
        test_harness_source=harness,
        solc_version="0.8.24",
        foundry_image=image,
        positive_control_test="test_positive_control_reentrancy_drains_vulnerable_vault",
        negative_control_test="test_negative_control_safe_vault_resists_same_attack",
        priority=1,
        disclosure_deadline_days=30,
    )
    case = ResearchCase(
        case_id="foundry-worker-e2e-" + target_commit[:12],
        target_repository="acme/reentrancy-vault",
        target_commit=target_commit,
        scope_url="https://example.invalid/local-benchmark-scope",
        scope_digest=hashlib.sha256(b"local benchmark scope").hexdigest(),
        scope_reviewed_on=date.today().isoformat(),
        hypothesis=spec.hypothesis,
        attacker_capability="Local Foundry harness only; no network or live transaction.",
        expected_invariant="A vault credit can be consumed at most once.",
        falsification_criteria=spec.falsification_criteria,
        execution_mode=ExecutionMode.LOCAL,
        allowed_techniques=("runtime_probe",),
        rounds=(spec,),
    )

    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "worker-e2e.db")
    monkeypatch.setenv("AEGISFORGE_TARGET_CHECKOUT_ROOT", str(repository_root))
    monkeypatch.setenv("AEGISFORGE_SOLC_BINARY", compiler)
    monkeypatch.setenv("AEGISFORGE_DOCKER_RUNTIME_AUTHORIZED", "1")
    queue = TaskQueue()
    try:
        queue.register_research_case(case)
        started = start_case_round(queue, case.case_id, spec.round_id)
        queue.claim("e2e-source-researcher", role="source_researcher")
        queue.finish(started["root_task_id"], result={"status": "INCONCLUSIVE"})
        task_id = queue.add(
            "Run real Foundry reentrancy benchmark",
            role="lab_runner",
            parent_task_id=started["root_task_id"],
        )

        worker = Worker.__new__(Worker)
        worker.role = "lab_runner"
        worker.worker_id = "foundry-worker-e2e"
        worker.agent_id = "foundry-worker-e2e-agent"
        worker.agent_identity = SimpleNamespace(
            to_dict=lambda: {"agent_id": "foundry-worker-e2e-agent"}
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
        assert result["status"] == "EXECUTED_PASS"
        assert result["test_counts"]["total"] >= 2
        assert result["control_tests"]["positive"]["status"] == "Success"
        assert result["control_tests"]["negative"]["status"] == "Success"
        assert result["local_experiment_evidence"]["status"] == "PERSISTED"
        assert result["local_experiment_evidence"]["experiment_status"] == "PASS"
        assert result["local_experiment_evidence"]["vulnerability_confirmed"] is False
        assert "stdout" not in result
        assert "stderr" not in result
    finally:
        queue.db.close()
