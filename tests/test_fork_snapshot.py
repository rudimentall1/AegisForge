import hashlib

import pytest

from agents.security_checker.fork_engine import (
    ForkSnapshotError,
    build_fork_snapshot,
    build_fork_snapshot_from_rpc,
)


def test_builds_normalized_fork_snapshot_from_verified_chain_and_runtime():
    runtime_bytecode = "0x6001600055"
    snapshot = build_fork_snapshot(
        chain_id=42161,
        block_number=250,
        block_hash="0x" + "ab" * 32,
        contract_address="0x" + "CD" * 20,
        runtime_bytecode=runtime_bytecode,
    )

    assert snapshot == {
        "schema": "aegisforge.fork_snapshot.v1",
        "chain_id": 42161,
        "block_number": 250,
        "block_hash": "0x" + "ab" * 32,
        "contract_address": "0x" + "cd" * 20,
        "runtime_bytecode": runtime_bytecode,
        "runtime_bytecode_sha256": hashlib.sha256(bytes.fromhex("6001600055")).hexdigest(),
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


def test_builds_snapshot_from_rpc_responses_and_pinned_code_request():
    block_hash = "0x" + "ab" * 32
    address = "0x" + "cd" * 20
    code = "0x6001600055"

    snapshot = build_fork_snapshot_from_rpc(
        chain_response={"jsonrpc": "2.0", "id": 1, "result": "0xa4b1"},
        block_response={
            "jsonrpc": "2.0",
            "id": 2,
            "result": {"number": "0xfa", "hash": block_hash},
        },
        code_response={"jsonrpc": "2.0", "id": 3, "result": code},
        code_request={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "eth_getCode",
            "params": [address, "0xfa"],
        },
        expected_chain_id=42161,
        expected_block_number=250,
        expected_block_hash=block_hash,
        contract_address=address,
        expected_response_ids=(1, 2, 3),
    )

    assert snapshot["chain_id"] == 42161
    assert snapshot["block_number"] == 250
    assert snapshot["block_hash"] == block_hash
    assert snapshot["runtime_bytecode"] == code


@pytest.mark.parametrize(
    ("response_field", "response"),
    [
        ("chain_response", {"jsonrpc": "2.0", "id": 99, "result": "0xa4b1"}),
        ("block_response", {"jsonrpc": "2.0", "id": 2, "result": {"number": "0xfa", "hash": "0x" + "bb" * 32}}),
        ("code_response", {"jsonrpc": "2.0", "id": 3, "result": "0x"}),
        ("code_response", {"jsonrpc": "2.0", "id": 3, "result": "0x123"}),
        ("code_response", {"jsonrpc": "2.0", "id": 3, "result": "0xzz"}),
    ],
)
def test_rejects_mismatched_or_invalid_rpc_snapshot_evidence(response_field, response):
    block_hash = "0x" + "ab" * 32
    address = "0x" + "cd" * 20
    values = {
        "chain_response": {"jsonrpc": "2.0", "id": 1, "result": "0xa4b1"},
        "block_response": {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {"number": "0xfa", "hash": block_hash},
        },
        "code_response": {"jsonrpc": "2.0", "id": 3, "result": "0x6001"},
        "code_request": {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "eth_getCode",
            "params": [address, "0xfa"],
        },
        "expected_chain_id": 42161,
        "expected_block_number": 250,
        "expected_block_hash": block_hash,
        "contract_address": address,
        "expected_response_ids": (1, 2, 3),
    }
    values[response_field] = response

    with pytest.raises(ForkSnapshotError):
        build_fork_snapshot_from_rpc(**values)


@pytest.mark.parametrize(
    "block_tag",
    ["latest", "pending", "0xf9", "0xfb"],
)
def test_rejects_code_observed_at_a_different_or_unpinned_block(block_tag):
    block_hash = "0x" + "ab" * 32
    address = "0x" + "cd" * 20

    with pytest.raises(ForkSnapshotError):
        build_fork_snapshot_from_rpc(
            chain_response={"jsonrpc": "2.0", "id": 1, "result": "0xa4b1"},
            block_response={
                "jsonrpc": "2.0",
                "id": 2,
                "result": {"number": "0xfa", "hash": block_hash},
            },
            code_response={"jsonrpc": "2.0", "id": 3, "result": "0x6001"},
            code_request={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "eth_getCode",
                "params": [address, block_tag],
            },
            expected_chain_id=42161,
            expected_block_number=250,
            expected_block_hash=block_hash,
            contract_address=address,
            expected_response_ids=(1, 2, 3),
        )
