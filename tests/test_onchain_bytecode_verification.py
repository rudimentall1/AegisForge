import hashlib
import json
import sqlite3

import pytest

from shared.onchain_target_store import OnchainTargetError, OnchainTargetRecord, OnchainTargetStore
from shared.solidity_bytecode_verifier import verify_compiler_runtime_match


def _standard_input():
    return json.dumps({
        "language": "Solidity",
        "sources": {"src/Vault.sol": {"content": "pragma solidity ^0.8.24; contract Vault {}"}},
        "settings": {
            "optimizer": {"enabled": True, "runs": 200},
            "evmVersion": "cancun",
            "outputSelection": {"*": {"*": ["evm.deployedBytecode"]}},
        },
    })


def _compiler_output(runtime="6001600055", *, immutable=None, links=None):
    deployed = {"object": runtime}
    if immutable is not None:
        deployed["immutableReferences"] = immutable
    if links is not None:
        deployed["linkReferences"] = links
    return {
        "contracts": {
            "src/Vault.sol": {
                "Vault": {"evm": {"deployedBytecode": deployed}}
            }
        }
    }


def _verify(**overrides):
    args = {
        "standard_json_input": _standard_input(),
        "compiler_output": _compiler_output(),
        "deployed_runtime_code": "0x6001600055",
        "expected_compiler_version": "0.8.24",
        "actual_compiler_version": "0.8.24",
        "contract_file": "src/Vault.sol",
        "contract_name": "Vault",
    }
    args.update(overrides)
    return verify_compiler_runtime_match(**args)


def test_exact_compiler_runtime_match_is_verified():
    result = _verify()
    assert result.status == "VERIFIED"
    assert result.reason == "runtime_bytecode_exact_match"
    assert result.deployed_runtime_sha256
    assert result.compiled_runtime_sha256 == result.deployed_runtime_sha256


def test_runtime_bytecode_mismatch_is_rejected():
    result = _verify(deployed_runtime_code="0x6002600055")
    assert result.status == "MISMATCH"
    assert result.reason == "runtime_bytecode_mismatch"


def test_missing_standard_json_compiler_metadata_is_incomplete():
    result = _verify(standard_json_input=None)
    assert result.status == "INCOMPLETE"
    assert result.reason == "standard_json_input_missing"


def test_wrong_compiler_version_is_incomplete():
    result = _verify(actual_compiler_version="0.8.25")
    assert result.status == "INCOMPLETE"
    assert result.reason == "compiler_version_mismatch"


def test_missing_deployed_bytecode_output_selection_is_incomplete():
    payload = json.loads(_standard_input())
    payload["settings"]["outputSelection"] = {"*": {"*": ["abi"]}}
    result = _verify(standard_json_input=json.dumps(payload))
    assert result.status == "INCOMPLETE"
    assert result.reason == "deployed_bytecode_output_not_requested"


def test_immutable_references_are_not_silently_masked():
    result = _verify(
        compiler_output=_compiler_output(
            "6001600000",
            immutable={"42": [{"start": 2, "length": 2}]},
        ),
        deployed_runtime_code="0x6001abcd00",
    )
    assert result.status == "INCOMPLETE"
    assert result.reason == "immutable_references_require_constructor_reconstruction"


def test_unresolved_library_references_are_not_silently_masked():
    result = _verify(
        compiler_output=_compiler_output(
            "60000000000000000000000000000000000000000000000000000000000000000000",
            links={"src/Math.sol": {"Math": [{"start": 1, "length": 20}]}},
        ),
        deployed_runtime_code="0x6001" + "11" * 20 + "00",
    )
    assert result.status == "INCOMPLETE"
    assert result.reason == "library_link_references_require_address_resolution"


def test_proxy_targets_are_not_misreported_as_implementation_verified():
    result = _verify(proxy_type="eip1967", implementations=("0x" + "2" * 40,))
    assert result.status == "INCOMPLETE"
    assert result.reason == "proxy_implementation_verification_required"



def test_target_store_persists_exact_runtime_code_with_its_digest():
    runtime = "0x6001600055"
    runtime_digest = hashlib.sha256(bytes.fromhex(runtime[2:])).hexdigest()
    record = OnchainTargetRecord(
        chain_id=8453,
        address="0x" + "1" * 40,
        block_number=123,
        block_hash="0x" + "2" * 64,
        runtime_code_sha256=runtime_digest,
        runtime_code=runtime,
        source_files={"src/Vault.sol": "contract Vault {}"},
        source_provider="blockscout_v2",
    )
    store = OnchainTargetStore(sqlite3.connect(":memory:"))
    target_id = store.put(record)
    restored = store.get(target_id)
    assert restored is not None
    assert restored.runtime_code == runtime
    assert restored.runtime_code_sha256 == runtime_digest


def test_target_store_rejects_runtime_code_digest_substitution():
    with pytest.raises(OnchainTargetError, match="runtime_code_sha256_mismatch"):
        OnchainTargetRecord(
            chain_id=8453,
            address="0x" + "1" * 40,
            block_number=123,
            block_hash="0x" + "2" * 64,
            runtime_code_sha256="3" * 64,
            runtime_code="0x6001600055",
            source_files={"src/Vault.sol": "contract Vault {}"},
            source_provider="blockscout_v2",
        )
