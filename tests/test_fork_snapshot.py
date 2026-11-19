import pytest

from agents.security_checker.fork_engine import (
    ForkSnapshotError,
    build_fork_snapshot,
)


def test_builds_immutable_fork_snapshot_from_verified_chain_and_runtime():
    snapshot = build_fork_snapshot(
        chain_id=42161,
        block_number=250,
        block_hash="0x" + "ab" * 32,
        contract_address="0x" + "CD" * 20,
        runtime_bytecode="0x6001600055",
    )

    assert snapshot == {
        "schema": "aegisforge.fork_snapshot.v1",
        "chain_id": 42161,
        "block_number": 250,
        "block_hash": "0x" + "ab" * 32,
        "contract_address": "0x" + "cd" * 20,
        "runtime_bytecode": "0x6001600055",
        "runtime_bytecode_sha256": "5b5a5f4f5e7c1b2a",
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("chain_id", True),
        ("chain_id", 0),
        ("block_number", -1),
        ("block_number", True),
        ("block_hash", "0x1234"),
        ("contract_address", "0x1234"),
        ("runtime_bytecode", "0x"),
        ("runtime_bytecode", "0x600"),
        ("runtime_bytecode", "6001600055"),
    ],
)
def test_rejects_invalid_fork_snapshot_inputs(field, value):
    values = {
        "chain_id": 42161,
        "block_number": 250,
        "block_hash": "0x" + "ab" * 32,
        "contract_address": "0x" + "cd" * 20,
        "runtime_bytecode": "0x6001600055",
    }
    values[field] = value

    with pytest.raises(ForkSnapshotError):
        build_fork_snapshot(**values)


def test_snapshot_hash_changes_when_runtime_bytecode_changes():
    first = build_fork_snapshot(
        chain_id=1,
        block_number=10,
        block_hash="0x" + "ab" * 32,
        contract_address="0x" + "cd" * 20,
        runtime_bytecode="0x6001",
    )
    second = build_fork_snapshot(
        chain_id=1,
        block_number=10,
        block_hash="0x" + "ab" * 32,
        contract_address="0x" + "cd" * 20,
        runtime_bytecode="0x6002",
    )

    assert first["runtime_bytecode_sha256"] != second["runtime_bytecode_sha256"]
