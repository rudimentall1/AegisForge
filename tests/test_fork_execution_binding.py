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
        "source_chain_id": 42161,
        "fork_chain_id": 31338,
        "block_number": 250,
        "block_hash": "0x" + "ab" * 32,
        "contract_address": "0x" + "cd" * 20,
        "runtime_bytecode_sha256": _snapshot()["runtime_bytecode_sha256"],
    }


def test_execution_anchor_is_bound_to_exact_snapshot():
    binding = validate_fork_execution_anchor(_snapshot(), _anchor())

    assert binding == {
        "schema": "aegisforge.fork_execution_binding.v1",
        "source_chain_id": 42161,
        "fork_chain_id": 31338,
        "block_number": 250,
        "block_hash": "0x" + "ab" * 32,
        "contract_address": "0x" + "cd" * 20,
        "runtime_bytecode_sha256": _snapshot()["runtime_bytecode_sha256"],
        "snapshot_bound": True,
    }


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("source_chain_id", 1, "fork_execution_chain_mismatch"),
        ("fork_chain_id", 0, "fork_execution_anchor_invalid"),
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



def _rpc_observations(*, chain_id="0x7b72", block_number="0xfa",
                      block_hash="0x" + "ab" * 32, code="0x6001600055"):
    return {
        "chain": {"jsonrpc": "2.0", "id": "fork-chain", "result": chain_id},
        "block": {
            "jsonrpc": "2.0",
            "id": "fork-block",
            "result": {"number": block_number, "hash": block_hash},
        },
        "code": {"jsonrpc": "2.0", "id": "fork-code", "result": code},
        "request": {
            "jsonrpc": "2.0",
            "id": "fork-code",
            "method": "eth_getCode",
            "params": ["0x" + "cd" * 20, "0xfa"],
        },
    }


def test_rpc_observation_binds_actual_fork_chain_block_and_runtime_code():
    from agents.security_checker.fork_engine import (
        validate_fork_execution_rpc_observation,
    )

    observed = _rpc_observations()
    result = validate_fork_execution_rpc_observation(
        _snapshot(),
        chain_response=observed["chain"],
        block_response=observed["block"],
        code_response=observed["code"],
        code_request=observed["request"],
        expected_response_ids=("fork-chain", "fork-block", "fork-code"),
    )

    assert result["snapshot_bound"] is True
    assert result["fork_rpc_observation_verified"] is True
    assert result["source_chain_id"] == 42161
    assert result["fork_chain_id"] == 31602
    assert result["block_number"] == 250
    assert result["runtime_bytecode_sha256"] == _snapshot()["runtime_bytecode_sha256"]


@pytest.mark.parametrize(
    ("observation", "expected_error"),
    [
        ({"chain_id": "0x0"}, "fork_execution_anchor_invalid"),
        ({"block_number": "0xfb"}, "fork_execution_block_mismatch"),
        ({"block_hash": "0x" + "ef" * 32}, "fork_execution_block_mismatch"),
        ({"code": "0x6002600055"}, "fork_execution_bytecode_mismatch"),
    ],
)
def test_rpc_observation_rejects_fork_state_not_matching_snapshot(
    observation, expected_error
):
    from agents.security_checker.fork_engine import (
        validate_fork_execution_rpc_observation,
    )

    observed = _rpc_observations(**observation)
    with pytest.raises(ForkSnapshotError, match=expected_error):
        validate_fork_execution_rpc_observation(
            _snapshot(),
            chain_response=observed["chain"],
            block_response=observed["block"],
            code_response=observed["code"],
            code_request=observed["request"],
            expected_response_ids=("fork-chain", "fork-block", "fork-code"),
        )


def test_rpc_observation_rejects_code_request_for_different_contract_or_block():
    from agents.security_checker.fork_engine import (
        validate_fork_execution_rpc_observation,
    )

    observed = _rpc_observations()
    observed["request"]["params"] = ["0x" + "ef" * 20, "0xfa"]
    with pytest.raises(ForkSnapshotError, match="fork_execution_code_request_invalid"):
        validate_fork_execution_rpc_observation(
            _snapshot(),
            chain_response=observed["chain"],
            block_response=observed["block"],
            code_response=observed["code"],
            code_request=observed["request"],
            expected_response_ids=("fork-chain", "fork-block", "fork-code"),
        )


def test_rpc_observation_rejects_response_id_mismatch():
    from agents.security_checker.fork_engine import (
        validate_fork_execution_rpc_observation,
    )

    observed = _rpc_observations()
    observed["code"]["id"] = "unexpected"
    with pytest.raises(ForkSnapshotError, match="code_response_invalid"):
        validate_fork_execution_rpc_observation(
            _snapshot(),
            chain_response=observed["chain"],
            block_response=observed["block"],
            code_response=observed["code"],
            code_request=observed["request"],
            expected_response_ids=("fork-chain", "fork-block", "fork-code"),
        )
