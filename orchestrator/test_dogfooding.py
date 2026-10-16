"""Bounded synthetic dogfooding across the real local research boundaries.

This is calibration only. It deliberately does not create or assert a finding,
execute a Solidity target, contact a network, or use real wallet/key material.
"""
from copy import deepcopy

import pytest

from agents.lab_runner.agent import LabRunner
from agents.validator.agent import Validator
from orchestrator.task_graph import ExecutionStatus, TaskGraph, TaskGraphError, TaskNode
from shared.evidence_manifest import (
    EvidenceManifestError,
    build_manifest,
    digest,
    verify_manifest,
)
from shared.research_case import ResearchCase, research_case_binding
from shared.scope_gate import validate_case
from shared.task import Task


def _case() -> ResearchCase:
    return ResearchCase(
        case_id="synthetic-dogfood-2026-01",
        target_repository="rudimentall1/AegisForge",
        target_commit="a" * 40,
        scope_url="https://example.com/internal-synthetic-fixture",
        scope_digest="b" * 64,
        scope_reviewed_on="2026-10-16",
        hypothesis="A deliberately small synthetic seed space is exhaustible.",
        attacker_capability="The test harness can enumerate a repository-owned toy seed space.",
        expected_invariant="Only synthetic fixture values are recovered.",
        falsification_criteria="The lab fails if the fixed synthetic test vector is not recovered.",
        execution_mode="local",
        status="ready",
    )


def _graph() -> TaskGraph:
    return TaskGraph(
        [
            TaskNode("scope", "scope_gate", timeout_seconds=5),
            TaskNode("lab", "lab_runner", dependencies=("scope",), timeout_seconds=10),
            TaskNode("verify", "validator", dependencies=("lab",), timeout_seconds=10),
            TaskNode("bundle", "evidence_bundle", dependencies=("verify",), timeout_seconds=5),
        ],
        max_parallelism=2,
        max_resource_units=2,
    )


def _validate_lab_result(experiment: dict) -> dict:
    validator = Validator.__new__(Validator)
    validator.source_fetcher = lambda _url: {}
    task = Task(
        task_id="synthetic-dogfood-validator",
        description="Validate a repository-owned synthetic lab receipt",
        result={
            "research_track": "evm_key_forensics",
            "stage": "lab",
            "sources": [],
            "hypotheses": [],
            "lab_experiments": [experiment],
        },
    )
    completed = validator.run(task)
    assert completed.status == "validated"
    return completed.result["research_validation"]


def test_synthetic_dogfood_runs_through_gate_lab_verifier_and_manifest():
    case = _case()
    graph = _graph()
    statuses: dict[str, ExecutionStatus] = {}

    assert graph.plan(statuses).ready == ("scope",)
    gate = validate_case(case)
    assert gate.allowed is True
    assert gate.status == "ALLOW"
    statuses["scope"] = ExecutionStatus.SUCCEEDED

    assert graph.plan(statuses).ready == ("lab",)
    task = Task(
        task_id="synthetic-dogfood-lab",
        description="Run repository-owned synthetic entropy demonstration only",
        payload={"research_case_id": case.case_id, "research_case": case},
    )
    lab_task = LabRunner().run(task)
    experiment = lab_task.result["lab_experiments"][0]
    summary = lab_task.result["lab_summary"]

    # A status is successful only when the subprocess itself reports success.
    if summary.get("synthetic_subprocess_passed") is not True:
        statuses["lab"] = (
            ExecutionStatus.TIMED_OUT
            if experiment.get("execution_record", {}).get("timed_out") is True
            else ExecutionStatus.FAILED
        )
        plan = graph.plan(statuses)
        assert "verify" in plan.blocked
        assert "bundle" in plan.blocked
        pytest.fail("synthetic subprocess did not pass; downstream stages were blocked")

    assert summary["claim_status"] == "ILLUSTRATIVE_ONLY"
    assert summary["historical_implementation_reproduced"] is False
    assert summary["real_private_keys_used"] is False
    assert summary["live_addresses_examined"] == 0
    assert experiment["synthetic_test_only"] is True
    assert experiment["uses_real_private_keys"] is False
    assert experiment["uses_real_wallet_addresses"] is False
    assert experiment["public_wallets_touched"] == 0
    assert experiment["execution_receipt"]["inputs"]["research_case"]["case_id"] == case.case_id
    statuses["lab"] = ExecutionStatus.SUCCEEDED

    assert graph.plan(statuses).ready == ("verify",)
    validation = _validate_lab_result(experiment)
    assert validation["lab_execution_receipts_checked"] == 1
    assert validation["lab_execution_receipts_integrity_verified"] is True
    assert validation["lab_execution_receipts_trusted"] is False
    assert validation["historical_reproduction_confirmed"] is False
    statuses["verify"] = ExecutionStatus.SUCCEEDED

    assert graph.plan(statuses).ready == ("bundle",)
    binding = research_case_binding(case)
    manifest = build_manifest(
        [
            {
                "id": case.case_id,
                "type": "research_case_binding",
                "digest": digest(binding),
            },
            {
                "id": experiment["experiment_id"],
                "type": "synthetic_execution_receipt",
                "digest": digest(experiment["execution_receipt"]),
            },
            {
                "id": "synthetic-validator-result",
                "type": "validation_result",
                "digest": digest(validation),
            },
        ],
        agent_id="aegisforge-synthetic-dogfood",
    )
    verified = verify_manifest(manifest)
    assert verified["valid"] is True
    assert verified["entry_count"] == 3
    statuses["bundle"] = ExecutionStatus.SUCCEEDED
    assert graph.plan(statuses).ready == ()

    # The pipeline output is a calibration artifact, never a research finding.
    assert "CONFIRMED" not in str(manifest)
    assert "REJECTED" not in str(manifest)


def test_scope_gate_failure_blocks_lab_and_all_downstream_stages():
    assert validate_case(None).allowed is False
    plan = _graph().plan({"scope": "FAILED"})
    assert plan.ready == ()
    assert plan.blocked == ("lab", "verify", "bundle")


def test_tampered_synthetic_manifest_is_rejected():
    case = _case()
    manifest = build_manifest(
        [
            {
                "id": case.case_id,
                "type": "research_case_binding",
                "digest": digest(research_case_binding(case)),
            },
            {
                "id": "synthetic-receipt",
                "type": "synthetic_execution_receipt",
                "digest": digest({"test_only": True}),
            },
        ]
    )
    tampered = deepcopy(manifest)
    tampered["entries"][0]["digest"] = "0" * 64
    with pytest.raises(EvidenceManifestError, match="manifest_root_mismatch"):
        verify_manifest(tampered)
