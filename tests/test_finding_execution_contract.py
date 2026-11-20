import copy

import pytest

from agents.security_checker.finding_execution_contract import (
    FindingExecutionContractError,
    build_finding_execution_request,
    validate_finding_execution_request,
)
from agents.security_checker.fork_engine import build_fork_snapshot
from agents.security_checker.fork_execution_plan import build_fork_execution_plan


def _snapshot():
    return build_fork_snapshot(
        chain_id=42161,
        block_number=123456,
        block_hash="0x" + "a" * 64,
        contract_address="0x" + "b" * 40,
        runtime_bytecode="0x6001600055",
    )


def _request(**overrides):
    snapshot = _snapshot()
    plan = build_fork_execution_plan(snapshot, fork_chain_id=31338)
    finding = {
        "repository": "owner/repo",
        "commit_sha": "c" * 40,
        "source_tree_sha256": "d" * 64,
        "detector_id": "slither.reentrancy-eth",
        "severity": "HIGH",
        "source_file": "contracts/Vault.sol",
        "line_start": 40,
        "line_end": 52,
        "contract_address": snapshot["contract_address"],
    }
    exploit_test = {
        "path": "tests/fork_exploits/vault_reentrancy.t.sol",
        "sha256": "e" * 64,
    }
    preconditions = [
        {"kind": "caller_role", "operator": "equals", "value": "untrusted"},
        {"kind": "balance", "operator": "greater_than", "value": 0},
    ]
    request = build_finding_execution_request(
        finding=finding,
        snapshot=snapshot,
        plan=plan,
        exploit_test=exploit_test,
        preconditions=preconditions,
        timeout_seconds=120,
        max_steps=50000,
    )
    request.update(overrides)
    return request, snapshot, plan, finding, exploit_test, preconditions


def test_request_is_deterministic_and_bound_to_finding_and_snapshot():
    request, snapshot, plan, finding, exploit_test, preconditions = _request()

    validated = validate_finding_execution_request(
        request, snapshot=snapshot, plan=plan
    )

    assert validated == request
    assert request["schema"] == "aegisforge.finding_execution_request.v1"
    assert request["finding_id"].startswith("sha256:")
    assert request["snapshot_sha256"] == plan["snapshot_sha256"]
    assert request["chain"]["block_hash"] == snapshot["block_hash"]
    assert request["execution"]["network_access"] is False
    assert request["execution"]["external_transactions_enabled"] is False
    assert request["dynamic_verified"] is False
    assert request["confirmed"] is False


def test_finding_identity_changes_when_source_or_detector_changes():
    request, snapshot, plan, finding, exploit_test, preconditions = _request()
    changed = dict(finding, line_start=41)

    other = build_finding_execution_request(
        finding=changed,
        snapshot=snapshot,
        plan=plan,
        exploit_test=exploit_test,
        preconditions=preconditions,
        timeout_seconds=120,
        max_steps=50000,
    )

    assert other["finding_id"] != request["finding_id"]


@pytest.mark.parametrize(
    "path",
    [
        "../malicious.t.sol",
        "test/Untrusted.t.sol",
        "tests/fork_exploits/../../evil.t.sol",
        "/tmp/evil.t.sol",
        "tests/fork_exploits/evil.sol",
    ],
)
def test_request_rejects_non_allowlisted_exploit_artifact(path):
    request, snapshot, plan, finding, exploit_test, preconditions = _request()
    exploit_test["path"] = path

    with pytest.raises(FindingExecutionContractError):
        build_finding_execution_request(
            finding=finding,
            snapshot=snapshot,
            plan=plan,
            exploit_test=exploit_test,
            preconditions=preconditions,
            timeout_seconds=120,
            max_steps=50000,
        )


def test_request_rejects_snapshot_or_plan_mismatch():
    request, snapshot, plan, finding, exploit_test, preconditions = _request()
    changed_snapshot = copy.deepcopy(snapshot)
    changed_snapshot["block_number"] += 1

    with pytest.raises(FindingExecutionContractError):
        validate_finding_execution_request(
            request, snapshot=changed_snapshot, plan=plan
        )


@pytest.mark.parametrize(
    "preconditions",
    [
        [{"kind": "arbitrary_shell", "operator": "execute", "value": "curl x"}],
        [{"kind": "balance", "operator": "equals", "value": "unbounded"}],
        [{"kind": "balance", "operator": "equals", "value": True}],
        [{"kind": "balance", "operator": "equals", "value": 1}] * 17,
    ],
)
def test_request_rejects_unbounded_or_unrecognized_preconditions(preconditions):
    request, snapshot, plan, finding, exploit_test, _ = _request()

    with pytest.raises(FindingExecutionContractError):
        build_finding_execution_request(
            finding=finding,
            snapshot=snapshot,
            plan=plan,
            exploit_test=exploit_test,
            preconditions=preconditions,
            timeout_seconds=120,
            max_steps=50000,
        )


def test_request_rejects_confirmation_flag_tampering():
    request, snapshot, plan, finding, exploit_test, preconditions = _request()
    request["confirmed"] = True

    with pytest.raises(FindingExecutionContractError):
        validate_finding_execution_request(
            request, snapshot=snapshot, plan=plan
        )
