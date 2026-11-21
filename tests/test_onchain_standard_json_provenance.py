import hashlib
import json
import sqlite3

import pytest

from scam_intelligence.contract_intake import (
    BlockscoutContractIntake,
    VerifiedContractSource,
)
from shared.onchain_target_store import OnchainTargetError, OnchainTargetRecord, OnchainTargetStore


def _standard_json():
    return {
        "language": "Solidity",
        "sources": {
            "src/Vault.sol": {"content": "pragma solidity ^0.8.24; contract Vault {}"}
        },
        "settings": {
            "optimizer": {"enabled": True, "runs": 777},
            "evmVersion": "cancun",
            "outputSelection": {"*": {"*": ["abi", "evm.bytecode", "ast"]}},
        },
    }


def _record(standard_json_input, digest=""):
    return OnchainTargetRecord(
        chain_id=8453,
        address="0x" + "1" * 40,
        block_number=123,
        block_hash="0x" + "2" * 64,
        runtime_code_sha256="3" * 64,
        source_files={"src/Vault.sol": "pragma solidity ^0.8.24; contract Vault {}"},
        source_provider="blockscout_v2",
        compiler_version="0.8.24",
        contract_name="Vault",
        standard_json_input=standard_json_input,
        standard_json_input_sha256=digest,
    )


def test_intake_preserves_exact_standard_json_string_bytes():
    raw = json.dumps(_standard_json(), separators=(",", ":")) + "\n"
    preserved = BlockscoutContractIntake._standard_json_input({"source_code": raw})
    assert preserved == raw
    assert hashlib.sha256(preserved.encode("utf-8")).hexdigest() == hashlib.sha256(raw.encode("utf-8")).hexdigest()


def test_intake_canonicalizes_standard_json_object_without_losing_settings():
    payload = _standard_json()
    preserved = BlockscoutContractIntake._standard_json_input({"source_code": payload})
    parsed = json.loads(preserved)
    assert parsed["settings"] == payload["settings"]
    assert parsed["sources"] == payload["sources"]


def test_intake_does_not_mistake_plain_solidity_for_standard_json():
    assert BlockscoutContractIntake._standard_json_input(
        {"source_code": "pragma solidity ^0.8.24; contract Vault {}"}
    ) is None


def test_verified_source_carries_standard_json_digest():
    raw = json.dumps(_standard_json(), separators=(",", ":"))
    source = VerifiedContractSource(
        chain_id=8453,
        address="0x" + "1" * 40,
        contract_name="Vault",
        compiler_version="0.8.24",
        optimization_enabled=True,
        evm_version="cancun",
        source_files={"src/Vault.sol": _standard_json()["sources"]["src/Vault.sol"]["content"]},
        standard_json_input=raw,
    )
    assert source.standard_json_input_sha256 == hashlib.sha256(raw.encode()).hexdigest()


def test_target_store_round_trips_standard_json_input_and_settings():
    raw = json.dumps(_standard_json(), separators=(",", ":"))
    db = sqlite3.connect(":memory:")
    store = OnchainTargetStore(db)
    record = _record(raw)
    target_id = store.put(record)
    restored = store.get(target_id)
    assert restored is not None
    assert restored.standard_json_input == raw
    assert restored.standard_json_input_sha256 == hashlib.sha256(raw.encode()).hexdigest()
    assert json.loads(restored.standard_json_input)["settings"]["optimizer"]["runs"] == 777


def test_target_store_rejects_standard_json_digest_substitution():
    raw = json.dumps(_standard_json(), separators=(",", ":"))
    with pytest.raises(OnchainTargetError, match="standard_json_input_sha256_mismatch"):
        _record(raw, "f" * 64)


def test_target_store_rejects_malformed_standard_json_input():
    with pytest.raises(OnchainTargetError, match="standard_json_input_invalid"):
        _record('{"sources": []}')


def test_target_store_rejects_oversized_standard_json_input():
    raw = json.dumps({"sources": {}, "padding": "x" * (8 * 1024 * 1024)})
    with pytest.raises(OnchainTargetError, match="standard_json_input_too_large"):
        _record(raw)
