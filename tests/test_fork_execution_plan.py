import copy
import hashlib
import json

import pytest

from agents.security_checker.fork_engine import build_fork_snapshot
from agents.security_checker.fork_execution_plan import (
    ForkExecutionPlanError,
    build_fork_execution_plan,
    build_fork_runtime_compose_environment,
    validate_fork_execution_plan,
)


def _snapshot():
    return build_fork_snapshot(
        chain_id=42161,
        block_number=123456,
        block_hash="0x" + "a" * 64,
        contract_address="0x" + "b" * 40,
        runtime_bytecode="0x6001600055",
    )


def test_execution_plan_binds_snapshot_and_uses_fixed_internal_endpoints():
    snapshot = _snapshot()

    plan = build_fork_execution_plan(
        snapshot,
        fork_chain_id=31338,
        timeout_seconds=240,
    )

    canonical = json.dumps(
        snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    assert plan["schema"] == "aegisforge.fork_execution_plan.v1"
    assert plan["snapshot_sha256"] == hashlib.sha256(canonical).hexdigest()
    assert plan["source_chain_id"] == 42161
    assert plan["fork_chain_id"] == 31338
    assert plan["block_number"] == 123456
    assert plan["block_hash"] == "0x" + "a" * 64
    assert plan["contract_address"] == "0x" + "b" * 40
    assert plan["runtime_bytecode_sha256"] == snapshot["runtime_bytecode_sha256"]
    assert plan["anvil_rpc_url"] == "http://anvil:8545"
    assert plan["adapter_rpc_url"] == "http://anvil-rpc-adapter:8546"
    assert plan["required_network_profile"] == "gateway_mediated_internal_v1"
    assert plan["local_fork_transactions_enabled"] is True
    assert plan["external_transactions_enabled"] is False
    assert plan["dynamic_verified"] is False
    assert plan["confirmed"] is False
    assert validate_fork_execution_plan(plan, snapshot) == plan


def test_execution_plan_rejects_snapshot_tampering():
    snapshot = _snapshot()
    plan = build_fork_execution_plan(snapshot, fork_chain_id=31338)
    tampered = copy.deepcopy(snapshot)
    tampered["runtime_bytecode"] = "0x6002600055"

    with pytest.raises(ForkExecutionPlanError, match="snapshot_invalid"):
        validate_fork_execution_plan(plan, tampered)


def test_execution_plan_rejects_plan_anchor_mismatch():
    snapshot = _snapshot()
    plan = build_fork_execution_plan(snapshot, fork_chain_id=31338)
    plan["block_hash"] = "0x" + "c" * 64

    with pytest.raises(ForkExecutionPlanError, match="snapshot_binding_mismatch"):
        validate_fork_execution_plan(plan, snapshot)


@pytest.mark.parametrize("timeout", [True, 0, 1801, "30", None])
def test_execution_plan_rejects_invalid_timeout(timeout):
    with pytest.raises(ForkExecutionPlanError, match="timeout_invalid"):
        build_fork_execution_plan(
            _snapshot(),
            fork_chain_id=31338,
            timeout_seconds=timeout,
        )


def test_execution_plan_rejects_invalid_fork_chain_id():
    with pytest.raises(ForkExecutionPlanError, match="fork_chain_id_invalid"):
        build_fork_execution_plan(_snapshot(), fork_chain_id=True)


def test_execution_plan_rejects_unexpected_fields():
    snapshot = _snapshot()
    plan = build_fork_execution_plan(snapshot, fork_chain_id=31338)
    plan["provider_url"] = "https://attacker.example/rpc"

    with pytest.raises(ForkExecutionPlanError, match="plan_schema_invalid"):
        validate_fork_execution_plan(plan, snapshot)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("anvil_rpc_url", "http://attacker.example:8545"),
        ("adapter_rpc_url", "http://127.0.0.1:8546"),
        ("local_fork_transactions_enabled", False),
        ("external_transactions_enabled", True),
        ("dynamic_verified", True),
        ("confirmed", True),
    ],
)
def test_execution_plan_rejects_endpoint_or_trust_policy_override(field, value):
    snapshot = _snapshot()
    plan = build_fork_execution_plan(snapshot, fork_chain_id=31338)
    plan[field] = value

    with pytest.raises(ForkExecutionPlanError, match="snapshot_binding_mismatch"):
        validate_fork_execution_plan(plan, snapshot)



def test_runtime_environment_contains_only_snapshot_pinned_compose_values():
    snapshot = _snapshot()
    plan = build_fork_execution_plan(
        snapshot,
        fork_chain_id=31338,
    )

    environment = build_fork_runtime_compose_environment(plan, snapshot)

    assert environment == {
        "AEGISFORGE_ANVIL_CHAIN_ID": "31338",
        "AEGISFORGE_ANVIL_FORK_BLOCK_NUMBER": "123456",
    }
    assert "AEGISFORGE_RPC_GATEWAY_TOKEN" not in environment
    assert "AEGISFORGE_RPC_GATEWAY_UPSTREAM_URL" not in environment
