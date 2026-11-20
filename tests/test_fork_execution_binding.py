import pytest

from agents.security_checker.fork_engine import (
    ForkSnapshotError,
    build_fork_snapshot,
    validate_fork_execution_anchor,
)


def _snapshot():
    return build_fork_snapshot(
        chain_id=42161,
        block_number=250,
        block_hash="0x" + "ab" * 32,
        contract_address="0x" + "cd" * 20,
        runtime_bytecode="0x6001600055",
    )


def _anchor():
    return {
        "chain_id": 42161,
        "block_number": 250,
        "block_hash": "0x" + "ab" * 32,
        "contract_address": "0x" + "cd" * 20,
        "runtime_bytecode_sha256": _snapshot()["runtime_bytecode_sha256"],
    }


def test_execution_anchor_is_bound_to_exact_snapshot():
    binding = validate_fork_execution_anchor(_snapshot(), _anchor())

    assert binding == {
        "schema": "aegisforge.fork_execution_binding.v1",
        "chain_id": 42161,
        "block_number": 250,
        "block_hash": "0x" + "ab" * 32,
        "contract_address": "0x" + "cd" * 20,
        "runtime_bytecode_sha256": _snapshot()["runtime_bytecode_sha256"],
        "snapshot_bound": True,
    }


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("chain_id", 1, "fork_execution_chain_mismatch"),
        ("block_number", 251, "fork_execution_block_mismatch"),
        ("block_hash", "0x" + "ef" * 32, "fork_execution_block_mismatch"),
        ("contract_address", "0x" + "ef" * 20, "fork_execution_contract_mismatch"),
        ("runtime_bytecode_sha256", "0" * 64, "fork_execution_bytecode_mismatch"),
    ],
)
def test_execution_anchor_rejects_evidence_not_bound_to_snapshot(field, value, error):
    anchor = _anchor()
    anchor[field] = value

    with pytest.raises(ForkSnapshotError, match=error):
        validate_fork_execution_anchor(_snapshot(), anchor)


def test_execution_anchor_rejects_missing_or_malformed_fields():
    anchor = _anchor()
    del anchor["runtime_bytecode_sha256"]

    with pytest.raises(ForkSnapshotError, match="fork_execution_anchor_invalid"):
        validate_fork_execution_anchor(_snapshot(), anchor)
