import hashlib
import json

import pytest

from agents.security_checker.fork_engine import (
    ForkSnapshotError,
    build_fork_snapshot,
    build_fork_snapshot_from_rpc,
    collect_fork_snapshot,
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


def test_collects_historical_snapshot_through_read_only_gateway(monkeypatch):
    import agents.security_checker.fork_engine as engine

    block_hash = "0x" + "ab" * 32
    address = "0x" + "cd" * 20
    observed_requests = []

    def fake_forward(url, allowed_hosts, body):
        request = json.loads(body)
        observed_requests.append(request)
        results = {
            "aegisforge-chain-id": "0xa4b1",
            "aegisforge-block": {
                "number": "0xfa",
                "hash": block_hash,
            },
            "aegisforge-code": "0x6001600055",
        }
        return {
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": results[request["id"]],
        }

    monkeypatch.setattr(engine, "forward_rpc_request", fake_forward)

    snapshot = collect_fork_snapshot(
        upstream_url="https://rpc.example.test/",
        allowed_hosts={"rpc.example.test"},
        expected_chain_id=42161,
        block_number=250,
        contract_address=address,
    )

    assert snapshot["chain_id"] == 42161
    assert snapshot["block_number"] == 250
    assert snapshot["block_hash"] == block_hash
    assert snapshot["runtime_bytecode"] == "0x6001600055"
    assert [item["method"] for item in observed_requests] == [
        "eth_chainId",
        "eth_getBlockByNumber",
        "eth_getCode",
        "eth_getBlockByNumber",
    ]
    assert observed_requests[1]["params"] == ["0xfa", False]
    assert observed_requests[2]["params"] == [address, "0xfa"]
    assert observed_requests[3]["params"] == ["0xfa", False]


def test_collect_snapshot_rejects_wrong_chain_identity(monkeypatch):
    import agents.security_checker.fork_engine as engine

    def fake_forward(url, allowed_hosts, body):
        request = json.loads(body)
        result = {
            "aegisforge-chain-id": "0x1",
            "aegisforge-block": {
                "number": "0xfa",
                "hash": "0x" + "ab" * 32,
            },
            "aegisforge-code": "0x6001",
            "aegisforge-block-confirmation": {
                "number": "0xfa",
                "hash": "0x" + "ab" * 32,
            },
        }[request["id"]]
        return {"jsonrpc": "2.0", "id": request["id"], "result": result}

    monkeypatch.setattr(engine, "forward_rpc_request", fake_forward)

    with pytest.raises(ForkSnapshotError):
        collect_fork_snapshot(
            upstream_url="https://rpc.example.test/",
            allowed_hosts={"rpc.example.test"},
            expected_chain_id=42161,
            block_number=250,
            contract_address="0x" + "cd" * 20,
        )



def test_collect_snapshot_rejects_reorg_between_block_and_code_reads(monkeypatch):
    import agents.security_checker.fork_engine as engine

    original_hash = "0x" + "ab" * 32
    replacement_hash = "0x" + "ef" * 32
    address = "0x" + "cd" * 20
    block_reads = 0

    def fake_forward(url, allowed_hosts, body):
        nonlocal block_reads
        request = json.loads(body)
        if request["method"] == "eth_getBlockByNumber":
            block_reads += 1
            block_hash = original_hash if block_reads == 1 else replacement_hash
            result = {"number": "0xfa", "hash": block_hash}
        elif request["method"] == "eth_chainId":
            result = "0xa4b1"
        else:
            result = "0x6001600055"
        return {"jsonrpc": "2.0", "id": request["id"], "result": result}

    monkeypatch.setattr(engine, "forward_rpc_request", fake_forward)

    with pytest.raises(
        ForkSnapshotError,
        match="fork_block_changed_during_collection",
    ):
        collect_fork_snapshot(
            upstream_url="https://rpc.example.test/",
            allowed_hosts={"rpc.example.test"},
            expected_chain_id=42161,
            block_number=250,
            contract_address=address,
        )

    assert block_reads == 2


@pytest.mark.parametrize(
    ("confirmation", "expected_error"),
    [
        ({"jsonrpc": "2.0", "id": "wrong-id", "result": {"number": "0xfa", "hash": "0x" + "ab" * 32}},
         "block_confirmation_response_invalid"),
        ({"jsonrpc": "2.0", "id": "aegisforge-block-confirmation", "result": None},
         "fork_block_confirmation_invalid"),
    ],
)
def test_collect_snapshot_fails_closed_on_invalid_block_confirmation(
    monkeypatch, confirmation, expected_error
):
    import agents.security_checker.fork_engine as engine

    block_hash = "0x" + "ab" * 32
    address = "0x" + "cd" * 20

    def fake_forward(url, allowed_hosts, body):
        request = json.loads(body)
        if request["method"] == "eth_getBlockByNumber":
            if request["id"] == "aegisforge-block-confirmation":
                return confirmation
            result = {"number": "0xfa", "hash": block_hash}
        elif request["method"] == "eth_chainId":
            result = "0xa4b1"
        else:
            result = "0x6001600055"
        return {"jsonrpc": "2.0", "id": request["id"], "result": result}

    monkeypatch.setattr(engine, "forward_rpc_request", fake_forward)

    with pytest.raises(ForkSnapshotError, match=expected_error):
        collect_fork_snapshot(
            upstream_url="https://rpc.example.test/",
            allowed_hosts={"rpc.example.test"},
            expected_chain_id=42161,
            block_number=250,
            contract_address=address,
        )
