"""Real solc + Anvil integration for compiler/runtime equivalence.

The test is opt-in so ordinary unit-test runs remain hermetic. The dedicated CI
step enables it only after provisioning pinned solc and Foundry image artifacts.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
import sqlite3
import time
import urllib.request

import pytest

from shared.onchain_target_store import OnchainTargetRecord, OnchainTargetStore
from shared.onchain_verification_store import OnchainVerificationRecord, OnchainVerificationStore
from shared.solidity_compiler import verify_onchain_target


pytestmark = pytest.mark.skipif(
    os.getenv("AEGISFORGE_RUN_REAL_SOLC_INTEGRATION") != "1",
    reason="requires the dedicated real-solc/Anvil CI fixture",
)

_SOURCE_PATH = "src/AegisForgeFixture.sol"
_SOURCE = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract AegisForgeFixture {
    function ping() external pure returns (uint256) {
        return 42;
    }
}
"""
_COMPILER_VERSION = "0.8.24+commit.e11b9ed9"


def _rpc(url: str, method: str, params: list):
    request = urllib.request.Request(
        url,
        data=json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        payload = json.loads(response.read().decode("utf-8"))
    assert "error" not in payload, f"{method} RPC error: {payload.get('error')}"
    assert "result" in payload, f"{method} RPC result missing"
    return payload["result"]


def _wait_for_receipt(url: str, tx_hash: str) -> dict:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        receipt = _rpc(url, "eth_getTransactionReceipt", [tx_hash])
        if receipt is not None:
            return receipt
        time.sleep(0.1)
    raise AssertionError("Anvil deployment transaction was not mined")


def test_real_solc_matches_anvil_deployment_and_detects_one_byte_drift():
    from shared.solidity_compiler import compile_standard_json

    rpc_url = os.environ["AEGISFORGE_ANVIL_RPC_URL"]
    standard_input = json.dumps({
        "language": "Solidity",
        "sources": {_SOURCE_PATH: {"content": _SOURCE}},
        "settings": {
            "optimizer": {"enabled": False, "runs": 200},
            "evmVersion": "cancun",
            "outputSelection": {
                "*": {
                    "*": [
                        "evm.bytecode.object",
                        "evm.deployedBytecode.object",
                        "evm.deployedBytecode.immutableReferences",
                        "evm.deployedBytecode.linkReferences",
                    ]
                }
            },
        },
    }, sort_keys=True, separators=(",", ":"))

    compilation = compile_standard_json(standard_input, _COMPILER_VERSION)
    assert compilation.status == "COMPILED", compilation.reason
    assert compilation.compiler_version == _COMPILER_VERSION

    contract_output = compilation.compiler_output["contracts"][_SOURCE_PATH]["AegisForgeFixture"]
    creation_code = contract_output["evm"]["bytecode"]["object"]
    assert creation_code and len(creation_code) % 2 == 0

    accounts = _rpc(rpc_url, "eth_accounts", [])
    assert accounts, "Anvil did not expose an unlocked test account"
    tx_hash = _rpc(rpc_url, "eth_sendTransaction", [{
        "from": accounts[0],
        "data": "0x" + creation_code,
        "gas": "0x5b8d80",
    }])
    receipt = _wait_for_receipt(rpc_url, tx_hash)
    assert receipt.get("status") == "0x1", f"Anvil deployment reverted: {receipt}"
    address = receipt["contractAddress"]
    block_hash = receipt["blockHash"]
    block_number = int(receipt["blockNumber"], 16)

    deployed_runtime = _rpc(rpc_url, "eth_getCode", [
        address,
        {"blockHash": block_hash, "requireCanonical": True},
    ])
    runtime_bytes = bytes.fromhex(deployed_runtime[2:])
    assert runtime_bytes, "Anvil returned empty deployed runtime code"

    target = OnchainTargetRecord(
        chain_id=31337,
        address=address,
        block_number=block_number,
        block_hash=block_hash,
        runtime_code_sha256=hashlib.sha256(runtime_bytes).hexdigest(),
        runtime_code=deployed_runtime,
        source_files={_SOURCE_PATH: _SOURCE},
        source_provider="anvil-real-solc-integration-fixture",
        compiler_version=_COMPILER_VERSION,
        contract_name="AegisForgeFixture",
        standard_json_input=standard_input,
    )

    exact = verify_onchain_target(target, _SOURCE_PATH)
    assert exact.status == "VERIFIED", exact.reason
    assert exact.reason == "runtime_bytecode_exact_match"

    evidence_db = sqlite3.connect(":memory:")
    target_store = OnchainTargetStore(evidence_db)
    target_store.put(target)
    verification_store = OnchainVerificationStore(target_store)
    evidence = OnchainVerificationRecord.from_target(
        target,
        status=exact.status,
        reason=exact.reason,
        compiler_version=compilation.compiler_version,
        compiler_binary_sha256=compilation.compiler_binary_sha256,
        compiled_runtime_sha256=exact.compiled_runtime_sha256,
        compiler_image=os.environ["AEGISFORGE_FOUNDRY_IMAGE"],
        isolation=compilation.isolation,
    )
    verification_id = verification_store.put(evidence)
    assert verification_store.get(verification_id) == evidence
    assert verification_store.list_for_target(target.target_id) == [evidence]

    mutated = bytearray(runtime_bytes)
    mutated[0] ^= 0x01
    mismatched_target = replace(
        target,
        runtime_code="0x" + mutated.hex(),
        runtime_code_sha256=hashlib.sha256(mutated).hexdigest(),
    )
    mismatch = verify_onchain_target(mismatched_target, _SOURCE_PATH)
    assert mismatch.status == "MISMATCH", mismatch.reason
    assert mismatch.reason == "runtime_bytecode_mismatch"
