import hashlib

import pytest

import shared.queue as queue_module
from shared.case_rounds import start_case_round
from shared.evidence_ledger import EvidenceLedger
from shared.queue import TaskQueue
from shared.research_case import (
    ExecutionMode,
    ResearchCase,
    RoundSpec,
    research_case_binding,
)
from shared.foundry_experiment_persistence import persist_foundry_lab_experiment


HARNESS = """pragma solidity 0.8.24;
contract AegisForgeValidationTest {
    function testPositiveControl() public pure {
        require(true, "positive");
    }
    function testNegativeControl() public pure {
        require(true, "negative");
    }
}
"""


def _fixture(monkeypatch, tmp_path, repository='acme/vault'):
    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "foundry-evidence.db")
    spec = RoundSpec(
        round_id="foundry-evidence-spec",
        technique="runtime_probe",
        hypothesis="A target invariant is violated by the planned test.",
        expected_evidence_atoms=("positive_control", "negative_control"),
        falsification_criteria="The negative control preserves the invariant.",
        target_source_paths=("src/Vault.sol",),
        test_harness_source=HARNESS,
        solc_version="0.8.24",
        foundry_image="ghcr.io/foundry-rs/foundry@sha256:" + ("d" * 64),
        positive_control_test="testPositiveControl",
        negative_control_test="testNegativeControl",
        priority=1,
        disclosure_deadline_days=30,
    )
    case = ResearchCase(
        case_id="foundry-evidence-case",
        target_repository=repository,
        target_commit="a" * 40,
        scope_url="https://example.com/scope",
        scope_digest=hashlib.sha256(b"scope").hexdigest(),
        scope_reviewed_on="2026-11-01",
        hypothesis=spec.hypothesis,
        attacker_capability="Local networkless Foundry test only",
        expected_invariant="A vault credit is consumed at most once.",
        falsification_criteria=spec.falsification_criteria,
        execution_mode=ExecutionMode.LOCAL,
        allowed_techniques=("runtime_probe",),
        rounds=(spec,),
    )
    queue = TaskQueue()
    queue.register_research_case(case)
    started = start_case_round(queue, case.case_id, spec.round_id)
    root_id = started["root_task_id"]
    queue.claim("root-worker", role="source_researcher")
    queue.finish(root_id, result={"status": "INCONCLUSIVE"})
    task_id = queue.add("Execute pinned Foundry harness", role="lab_runner", parent_task_id=root_id)
    claimed = queue.claim("foundry-worker", role="lab_runner")
    assert claimed[0] == task_id
    return queue, case, spec, started, task_id


def _result(case, spec, started, task_id):
    stdout = "forge test: 1 passed\n"
    stderr = ""
    return {
        "execution_adapter": "foundry_test",
        "research_track": "foundry_runtime_probe",
        "case_id": case.case_id,
        "round_id": started["round_id"],
        "round_spec_id": spec.round_id,
        "target_repository": case.target_repository,
        "target_commit": case.target_commit,
        "scope_digest": case.scope_digest,
        "source_provenance": "git_object_database_at_verified_commit",
        "pinned_source_tree_sha256": "b" * 64,
        "source_sha256": {"src/Vault.sol": "c" * 64},
        "test_harness_sha256": hashlib.sha256(HARNESS.encode()).hexdigest(),
        "test_harness_provenance": "immutable_research_case_round_spec",
        "compiler_version": "0.8.24",
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
        "research_case_binding": research_case_binding(case),
        "dynamic_verified": False,
        "confirmed": False,
        "vulnerability_confirmed": False,
    }


def test_foundry_observation_is_persisted_without_confirming_vulnerability(
    monkeypatch, tmp_path
):
    queue, case, spec, started, task_id = _fixture(monkeypatch, tmp_path)
    try:
        result = _result(case, spec, started, task_id)
        queue.finish(task_id, result=result)
        evidence = persist_foundry_lab_experiment(
            queue=queue,
            ledger=EvidenceLedger(queue.db),
            task_id=task_id,
            role="lab_runner",
            research_case=case,
            round_spec=spec,
            result_value=result,
        )
        assert evidence["status"] == "PERSISTED"
        assert evidence["execution_status"] == "EXECUTED_PASS"
        assert evidence["dynamic_verified"] is False
        assert evidence["vulnerability_confirmed"] is False
        assert evidence["authenticated_execution"] is False
    finally:
        queue.db.close()


def test_foundry_persistence_rejects_tampered_stdout(monkeypatch, tmp_path):
    queue, case, spec, started, task_id = _fixture(monkeypatch, tmp_path)
    try:
        result = _result(case, spec, started, task_id)
        result["stdout"] += "tampered"
        queue.finish(task_id, result=result)
        with pytest.raises(ValueError, match="foundry_stdout_digest_mismatch"):
            persist_foundry_lab_experiment(
                queue=queue,
                ledger=EvidenceLedger(queue.db),
                task_id=task_id,
                role="lab_runner",
                research_case=case,
                round_spec=spec,
                result_value=result,
            )
    finally:
        queue.db.close()


def test_foundry_partial_run_is_not_stored_as_passing_experiment(
    monkeypatch, tmp_path
):
    queue, case, spec, started, task_id = _fixture(monkeypatch, tmp_path)
    try:
        result = _result(case, spec, started, task_id)
        result["status"] = "PARTIAL_EXECUTION"
        queue.finish(task_id, result=result)
        evidence = persist_foundry_lab_experiment(
            queue=queue,
            ledger=EvidenceLedger(queue.db),
            task_id=task_id,
            role="lab_runner",
            research_case=case,
            round_spec=spec,
            result_value=result,
        )
        assert evidence["status"] == "PERSISTED"
        assert evidence["experiment_status"] == "FAIL"
        assert evidence["vulnerability_confirmed"] is False
    finally:
        queue.db.close()


def test_foundry_persistence_rejects_missing_negative_control_success(
    monkeypatch, tmp_path
):
    queue, case, spec, started, task_id = _fixture(monkeypatch, tmp_path)
    try:
        result = _result(case, spec, started, task_id)
        result["control_tests"]["negative"]["status"] = "Failure"
        result["test_statuses"]["testNegativeControl"] = "Failure"
        queue.finish(task_id, result=result)
        with pytest.raises(ValueError, match="foundry_required_control_test_evidence_missing"):
            persist_foundry_lab_experiment(
                queue=queue,
                ledger=EvidenceLedger(queue.db),
                task_id=task_id,
                role="lab_runner",
                research_case=case,
                round_spec=spec,
                result_value=result,
            )
    finally:
        queue.db.close()


def test_foundry_not_run_attempt_is_still_persisted_as_not_run(
    monkeypatch, tmp_path
):
    queue, case, spec, started, task_id = _fixture(monkeypatch, tmp_path)
    try:
        result = _result(case, spec, started, task_id)
        result.update({
            "status": "NOT_CONFIGURED",
            "exit_code": None,
            "command": ["forge", "test", "--offline"],
            "stdout": "",
            "stderr": "",
            "stdout_sha256": hashlib.sha256(b"").hexdigest(),
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "test_statuses": {},
            "control_tests": {
                "positive": {"name": "testPositiveControl", "status": None},
                "negative": {"name": "testNegativeControl", "status": None},
            },
        })
        queue.finish(task_id, result=result)
        evidence = persist_foundry_lab_experiment(
            queue=queue,
            ledger=EvidenceLedger(queue.db),
            task_id=task_id,
            role="lab_runner",
            research_case=case,
            round_spec=spec,
            result_value=result,
        )
        assert evidence["status"] == "PERSISTED"
        assert evidence["experiment_status"] == "NOT_RUN"
        assert evidence["vulnerability_confirmed"] is False
    finally:
        queue.db.close()


def test_foundry_persistence_normalizes_explicit_github_target_url(
    monkeypatch, tmp_path
):
    queue, case, spec, started, task_id = _fixture(
        monkeypatch, tmp_path, repository="https://github.com/acme/vault.git"
    )
    try:
        result = _result(case, spec, started, task_id)
        queue.finish(task_id, result=result)
        evidence = persist_foundry_lab_experiment(
            queue=queue,
            ledger=EvidenceLedger(queue.db),
            task_id=task_id,
            role="lab_runner",
            research_case=case,
            round_spec=spec,
            result_value=result,
        )
        assert evidence["status"] == "PERSISTED"
        assert evidence["experiment_status"] == "PASS"
    finally:
        queue.db.close()
