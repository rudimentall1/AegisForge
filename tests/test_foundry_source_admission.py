import hashlib
from dataclasses import replace
import subprocess

import pytest

import shared.queue as queue_module
from shared.case_rounds import start_case_round
from shared.queue import TaskQueue
from shared.research_case import ExecutionMode, ResearchCase, RoundSpec
from shared.target_execution_admission import (
    AdapterProfile,
    TargetExecutionAdmissionError,
    TargetExecutionRequest,
    resolve_foundry_sources,
    resolve_foundry_execution_inputs,
    run_admitted_foundry_round,
)


def _git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _checkout(tmp_path):
    root = tmp_path / "target"
    root.mkdir()
    subprocess.run(["git", "init", str(root)], check=True, capture_output=True)
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "Test")
    source = root / "src" / "Vault.sol"
    source.parent.mkdir()
    source.write_text("pragma solidity 0.8.24; contract Vault {}\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "src/Vault.sol"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-m", "fixture"], check=True, capture_output=True)
    commit = _git(root, "rev-parse", "HEAD")
    _git(root, "remote", "add", "origin", "https://github.com/acme/vault.git")
    return root, commit


def _case(commit, source_paths=("src/Vault.sol",)):
    spec = RoundSpec(
        round_id="foundry-round",
        technique="runtime_probe",
        hypothesis="The vault permits repeated withdrawal before credit is cleared.",
        expected_evidence_atoms=("positive_control", "negative_control"),
        falsification_criteria="A safe control resists the same reentrant callback.",
        target_source_paths=source_paths,
        priority=1,
        disclosure_deadline_days=30,
    )
    return ResearchCase(
        case_id="foundry-source-case",
        target_repository="acme/vault",
        target_commit=commit,
        scope_url="https://example.com/scope",
        scope_digest=hashlib.sha256(b"scope").hexdigest(),
        scope_reviewed_on="2026-11-01",
        hypothesis=spec.hypothesis,
        attacker_capability="Local test harness only",
        expected_invariant="A withdrawal cannot consume credit more than once.",
        falsification_criteria=spec.falsification_criteria,
        execution_mode=ExecutionMode.LOCAL,
        allowed_techniques=("runtime_probe",),
        rounds=(spec,),
    )


def _running_task(monkeypatch, tmp_path, case):
    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "queue.db")
    queue = TaskQueue()
    queue.register_research_case(case)
    started = start_case_round(queue, case.case_id, case.rounds[0].round_id)
    child = queue.add("Run approved Foundry source probe", role="lab_runner",
                      parent_task_id=started["root_task_id"])
    queue.db.execute(
        "UPDATE queue SET status='completed', result='{}', finished_at='2026-11-14T00:00:00+00:00' WHERE id=?",
        (started["root_task_id"],),
    )
    queue.db.commit()
    claimed = queue.claim("foundry-test-worker", role="lab_runner")
    assert claimed[0] == child
    return queue, child


def test_resolves_only_round_declared_sources_from_pinned_commit(monkeypatch, tmp_path):
    checkout, commit = _checkout(tmp_path)
    case = _case(commit)
    queue, task_id = _running_task(monkeypatch, tmp_path, case)
    try:
        # A mutable worktree edit must not alter what the Foundry adapter receives.
        (checkout / "src" / "Vault.sol").write_text("contract AttackerControlled {}\n")
        admitted, source_bundle = resolve_foundry_sources(
            queue, TargetExecutionRequest(task_id, AdapterProfile.FOUNDRY_TEST),
            checkout_root=checkout,
        )
        assert admitted.case_id == case.case_id
        assert source_bundle["target_commit"] == commit
        assert source_bundle["sources"]["src/Vault.sol"] == (
            "pragma solidity 0.8.24; contract Vault {}\n"
        )
        assert source_bundle["source_provenance"] == "git_object_database_at_verified_commit"
    finally:
        queue.db.close()


def test_foundry_source_resolution_fails_closed_without_declared_paths(monkeypatch, tmp_path):
    checkout, commit = _checkout(tmp_path)
    case = _case(commit, source_paths=())
    queue, task_id = _running_task(monkeypatch, tmp_path, case)
    try:
        with pytest.raises(TargetExecutionAdmissionError, match="round_target_source_paths_required"):
            resolve_foundry_sources(
                queue, TargetExecutionRequest(task_id, AdapterProfile.FOUNDRY_TEST),
                checkout_root=checkout,
            )
    finally:
        queue.db.close()


def test_foundry_source_resolution_rejects_repository_or_commit_mismatch(monkeypatch, tmp_path):
    checkout, commit = _checkout(tmp_path)
    case = _case(commit)
    queue, task_id = _running_task(monkeypatch, tmp_path, case)
    try:
        _git(checkout, "remote", "set-url", "origin", "https://github.com/attacker/vault.git")
        with pytest.raises(TargetExecutionAdmissionError, match="target_git_origin_mismatch"):
            resolve_foundry_sources(
                queue, TargetExecutionRequest(task_id, AdapterProfile.FOUNDRY_TEST),
                checkout_root=checkout,
            )
    finally:
        queue.db.close()


def test_foundry_execution_inputs_are_bound_to_case_plan(monkeypatch, tmp_path):
    checkout, commit = _checkout(tmp_path)
    harness = """pragma solidity 0.8.24;
import {Vault} from "../src/Vault.sol";
contract AegisForgeValidationTest {
    function testPositiveControl() public {
        Vault vault = new Vault();
        require(address(vault) != address(0), "deployment failed");
    }
    function testNegativeControl() public pure {
        require(true, "safe control");
    }
}
"""
    spec_case = _case(commit)
    planned_spec = RoundSpec(
        round_id=spec_case.rounds[0].round_id,
        technique="runtime_probe",
        hypothesis=spec_case.rounds[0].hypothesis,
        expected_evidence_atoms=("positive_control", "negative_control"),
        falsification_criteria=spec_case.rounds[0].falsification_criteria,
        target_source_paths=("src/Vault.sol",),
        test_harness_source=harness,
        solc_version="0.8.24",
        foundry_image="ghcr.io/foundry-rs/foundry@sha256:" + ("d" * 64),
        positive_control_test="testPositiveControl",
        negative_control_test="testNegativeControl",
        priority=1,
        disclosure_deadline_days=30,
    )
    case = ResearchCase(
        case_id=spec_case.case_id,
        target_repository=spec_case.target_repository,
        target_commit=commit,
        scope_url=spec_case.scope_url,
        scope_digest=spec_case.scope_digest,
        scope_reviewed_on=spec_case.scope_reviewed_on,
        hypothesis=spec_case.hypothesis,
        attacker_capability=spec_case.attacker_capability,
        expected_invariant=spec_case.expected_invariant,
        falsification_criteria=spec_case.falsification_criteria,
        execution_mode=spec_case.execution_mode,
        allowed_techniques=("runtime_probe",),
        rounds=(planned_spec,),
    )
    queue, task_id = _running_task(monkeypatch, tmp_path, case)
    try:
        admitted, inputs = resolve_foundry_execution_inputs(
            queue, TargetExecutionRequest(task_id, AdapterProfile.FOUNDRY_TEST),
            checkout_root=checkout,
        )
        assert admitted.case_id == case.case_id
        assert inputs["compiler_version"] == "0.8.24"
        assert inputs["foundry_image"] == (
            "ghcr.io/foundry-rs/foundry@sha256:" + ("d" * 64)
        )
        assert inputs["test_harness_source"] == harness
        assert inputs["test_harness_provenance"] == "immutable_research_case_round_spec"
        assert inputs["sources"]["src/Vault.sol"].startswith("pragma solidity")
    finally:
        queue.db.close()


def test_foundry_execution_inputs_reject_missing_harness_or_compiler(monkeypatch, tmp_path):
    checkout, commit = _checkout(tmp_path)
    case = _case(commit)
    queue, task_id = _running_task(monkeypatch, tmp_path, case)
    try:
        with pytest.raises(
            TargetExecutionAdmissionError,
            match="round_foundry_harness_toolchain_required",
        ):
            resolve_foundry_execution_inputs(
                queue, TargetExecutionRequest(task_id, AdapterProfile.FOUNDRY_TEST),
                checkout_root=checkout,
            )
    finally:
        queue.db.close()


def test_admitted_foundry_runner_receives_repository_relative_source_layout(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("AEGISFORGE_DOCKER_RUNTIME_AUTHORIZED", "1")
    import agents.security_checker.foundry_runner as runner

    checkout, commit = _checkout(tmp_path)
    harness = """pragma solidity 0.8.24;
import {Vault} from "../src/Vault.sol";
contract AegisForgeValidationTest {
    function testPositiveControl() public {
        Vault vault = new Vault();
        require(address(vault) != address(0));
    }
    function testNegativeControl() public pure {
        require(true, "safe control");
    }
}
"""
    base = _case(commit)
    spec = RoundSpec(
        round_id=base.rounds[0].round_id,
        technique="runtime_probe",
        hypothesis=base.rounds[0].hypothesis,
        expected_evidence_atoms=("positive_control", "negative_control"),
        falsification_criteria=base.rounds[0].falsification_criteria,
        target_source_paths=("src/Vault.sol",),
        test_harness_source=harness,
        solc_version="0.8.24",
        foundry_image="ghcr.io/foundry-rs/foundry@sha256:" + ("d" * 64),
        positive_control_test="testPositiveControl",
        negative_control_test="testNegativeControl",
        priority=1,
        disclosure_deadline_days=30,
    )
    case = ResearchCase(
        case_id=base.case_id,
        target_repository=base.target_repository,
        target_commit=commit,
        scope_url=base.scope_url,
        scope_digest=base.scope_digest,
        scope_reviewed_on=base.scope_reviewed_on,
        hypothesis=base.hypothesis,
        attacker_capability=base.attacker_capability,
        expected_invariant=base.expected_invariant,
        falsification_criteria=base.falsification_criteria,
        execution_mode=ExecutionMode.LOCAL,
        allowed_techniques=("runtime_probe",),
        rounds=(spec,),
    )
    queue, task_id = _running_task(monkeypatch, tmp_path, case)
    observed = {}
    observed_statuses = {
        "testPositiveControl": "Success",
        "testNegativeControl": "Success",
    }
    runner_status = {"value": "EXECUTED_PASS"}

    def fake_runner(source_files, test_source, **kwargs):
        observed["source_files"] = source_files
        observed["test_source"] = test_source
        observed["kwargs"] = kwargs
        if runner_status["value"] == "NOT_CONFIGURED":
            return {
                "schema": "aegisforge.foundry_execution.v1",
                "status": "NOT_CONFIGURED",
                "error": "foundry_container_image_not_configured",
                "network_access": False,
                "host_filesystem_access": False,
                "project_mount_read_only": True,
                "transactions_sent": False,
                "test_statuses": {},
            }
        return {
            "schema": "aegisforge.foundry_execution.v1",
            "status": "EXECUTED_PASS",
            "dynamic_verified": False,
            "confirmed": False,
            "vulnerability_confirmed": False,
            "network_access": False,
            "host_filesystem_access": False,
            "project_mount_read_only": True,
            "transactions_sent": False,
            "test_statuses": dict(observed_statuses),
            "test_counts": {"total": 2, "passed": 2, "failed": 0, "skipped": 0},
        }

    monkeypatch.setattr(runner, "run_foundry_test", fake_runner)
    try:
        result = run_admitted_foundry_round(
            queue, TargetExecutionRequest(task_id, AdapterProfile.FOUNDRY_TEST),
            checkout_root=checkout,
        )
        assert "Vault.sol" in observed["source_files"]
        assert "src/Vault.sol" not in observed["source_files"]
        assert observed["test_source"] == harness
        assert observed["kwargs"]["compiler_version"] == "0.8.24"
        assert observed["kwargs"]["image"] == (
            "ghcr.io/foundry-rs/foundry@sha256:" + ("d" * 64)
        )
        assert result["target_commit"] == commit
        assert result["source_provenance"] == "git_object_database_at_verified_commit"
        assert result["control_tests"]["positive"]["status"] == "Success"
        assert result["control_tests"]["negative"]["status"] == "Success"
        assert result["vulnerability_confirmed"] is False

        observed_statuses.pop("testNegativeControl")
        invalid = run_admitted_foundry_round(
            queue, TargetExecutionRequest(task_id, AdapterProfile.FOUNDRY_TEST),
            checkout_root=checkout,
        )
        assert invalid["status"] == "CONTROL_COVERAGE_INVALID"
        assert invalid["test_passed"] is False

        runner_status["value"] = "NOT_CONFIGURED"
        not_run = run_admitted_foundry_round(
            queue, TargetExecutionRequest(task_id, AdapterProfile.FOUNDRY_TEST),
            checkout_root=checkout,
        )
        assert not_run["status"] == "NOT_CONFIGURED"
        assert not_run["execution_error"] == "foundry_container_image_not_configured"
        assert "error" not in not_run
    finally:
        queue.db.close()


def test_foundry_admission_rejects_stale_scope_review(monkeypatch, tmp_path):
    checkout, commit = _checkout(tmp_path)
    case = replace(_case(commit), scope_reviewed_on="2019-01-01")
    queue, task_id = _running_task(monkeypatch, tmp_path, case)
    try:
        with pytest.raises(
            TargetExecutionAdmissionError,
            match="scope_gate_rejected:scope_review_date_implausible",
        ):
            resolve_foundry_sources(
                queue, TargetExecutionRequest(task_id, AdapterProfile.FOUNDRY_TEST),
                checkout_root=checkout,
            )
    finally:
        queue.db.close()


def _checkout_with_benchmark_source_root(tmp_path):
    root = tmp_path / "benchmark-target"
    root.mkdir()
    subprocess.run(["git", "init", str(root)], check=True, capture_output=True)
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "Test")
    source = root / "benchmark" / "src" / "Vault.sol"
    source.parent.mkdir(parents=True)
    source.write_text("pragma solidity 0.8.24; contract Vault {}\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "benchmark/src/Vault.sol"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-m", "fixture"], check=True, capture_output=True)
    commit = _git(root, "rev-parse", "HEAD")
    _git(root, "remote", "add", "origin", "https://github.com/acme/vault.git")
    return root, commit


def test_foundry_source_root_maps_nested_repository_tree_into_generated_src(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("AEGISFORGE_DOCKER_RUNTIME_AUTHORIZED", "1")
    import agents.security_checker.foundry_runner as runner

    checkout, commit = _checkout_with_benchmark_source_root(tmp_path)
    harness = """pragma solidity 0.8.24;
import {Vault} from "../src/Vault.sol";
contract AegisForgeValidationTest {
    function testPositiveControl() public pure { require(true); }
    function testNegativeControl() public pure { require(true); }
}
"""
    base = _case(commit, source_paths=("benchmark/src/Vault.sol",))
    spec = RoundSpec(
        round_id=base.rounds[0].round_id,
        technique="runtime_probe",
        hypothesis=base.rounds[0].hypothesis,
        expected_evidence_atoms=("positive_control", "negative_control"),
        falsification_criteria=base.rounds[0].falsification_criteria,
        target_source_paths=("benchmark/src/Vault.sol",),
        foundry_source_root="benchmark/src",
        test_harness_source=harness,
        solc_version="0.8.24",
        foundry_image="ghcr.io/foundry-rs/foundry@sha256:" + ("d" * 64),
        positive_control_test="testPositiveControl",
        negative_control_test="testNegativeControl",
        priority=1,
        disclosure_deadline_days=30,
    )
    case = ResearchCase(
        case_id=base.case_id,
        target_repository=base.target_repository,
        target_commit=commit,
        scope_url=base.scope_url,
        scope_digest=base.scope_digest,
        scope_reviewed_on=base.scope_reviewed_on,
        hypothesis=base.hypothesis,
        attacker_capability=base.attacker_capability,
        expected_invariant=base.expected_invariant,
        falsification_criteria=base.falsification_criteria,
        execution_mode=ExecutionMode.LOCAL,
        allowed_techniques=("runtime_probe",),
        rounds=(spec,),
    )
    queue, task_id = _running_task(monkeypatch, tmp_path, case)
    observed = {}

    def fake_runner(source_files, test_source, **kwargs):
        observed["source_files"] = source_files
        observed["test_source"] = test_source
        return {
            "status": "EXECUTED_PASS",
            "test_statuses": {
                "testPositiveControl": "Success",
                "testNegativeControl": "Success",
            },
            "test_counts": {"total": 2, "passed": 2, "failed": 0, "skipped": 0},
            "dynamic_verified": False,
            "confirmed": False,
            "vulnerability_confirmed": False,
            "network_access": False,
            "host_filesystem_access": False,
            "project_mount_read_only": True,
            "transactions_sent": False,
        }

    monkeypatch.setattr(runner, "run_foundry_test", fake_runner)
    try:
        result = run_admitted_foundry_round(
            queue, TargetExecutionRequest(task_id, AdapterProfile.FOUNDRY_TEST),
            checkout_root=checkout,
        )
        assert set(observed["source_files"]) == {"Vault.sol"}
        assert result["foundry_source_root"] == "benchmark/src"
        assert observed["test_source"] == harness
    finally:
        queue.db.close()


def test_foundry_execution_requires_explicit_docker_runtime_authorization(
    monkeypatch, tmp_path
):
    checkout, commit = _checkout(tmp_path)
    case = _case(commit)
    queue, task_id = _running_task(monkeypatch, tmp_path, case)
    monkeypatch.delenv("AEGISFORGE_DOCKER_RUNTIME_AUTHORIZED", raising=False)
    try:
        with pytest.raises(
            TargetExecutionAdmissionError,
            match="docker_runtime_authorization_required",
        ):
            run_admitted_foundry_round(
                queue, TargetExecutionRequest(task_id, AdapterProfile.FOUNDRY_TEST),
                checkout_root=checkout,
            )
    finally:
        queue.db.close()
