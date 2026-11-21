import hashlib
import json
import sqlite3

import pytest

from shared.onchain_target_store import (
    OnchainTargetRecord,
    OnchainTargetStore,
    OnchainTargetError,
)


def _record(**overrides):
    values = {
        "chain_id": 8453,
        "address": "0x" + "a" * 40,
        "block_number": 123456,
        "block_hash": "0x" + "b" * 64,
        "runtime_code_sha256": "c" * 64,
        "source_files": {
            "src/Vault.sol": "pragma solidity ^0.8.24; contract Vault {}",
            "src/Math.sol": "library Math {}",
        },
        "source_provider": "blockscout_v2",
        "compiler_version": "v0.8.24+commit.e11b9ed9",
        "contract_name": "Vault",
        "proxy_type": None,
        "implementations": (),
    }
    values.update(overrides)
    return OnchainTargetRecord(**values)


def test_record_normalizes_address_and_derives_content_identity():
    record = _record(address="0x" + "A" * 40)

    assert record.address == "0x" + "a" * 40
    assert len(record.source_sha256) == 64
    assert len(record.target_id) == 64
    expected = hashlib.sha256(
        json.dumps(
            record.source_files,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
    ).hexdigest()
    assert record.source_sha256 == expected


def test_record_rejects_invalid_chain_address_block_and_hashes():
    with pytest.raises(OnchainTargetError, match="chain_id_invalid"):
        _record(chain_id=True)
    with pytest.raises(OnchainTargetError, match="contract_address_invalid"):
        _record(address="not-an-address")
    with pytest.raises(OnchainTargetError, match="block_number_invalid"):
        _record(block_number=-1)
    with pytest.raises(OnchainTargetError, match="block_hash_invalid"):
        _record(block_hash="0x1234")
    with pytest.raises(OnchainTargetError, match="runtime_code_sha256_invalid"):
        _record(runtime_code_sha256="z" * 64)


def test_record_rejects_path_traversal_and_oversized_source_bundle():
    with pytest.raises(OnchainTargetError, match="source_path_invalid"):
        _record(source_files={"../escape.sol": "contract Escape {}"})
    with pytest.raises(OnchainTargetError, match="source_bundle_too_large"):
        _record(source_files={"src/Large.sol": "x" * (4 * 1024 * 1024 + 1)})


def test_record_rejects_caller_supplied_wrong_source_digest():
    with pytest.raises(OnchainTargetError, match="source_sha256_mismatch"):
        _record(source_sha256="0" * 64)


def test_store_round_trips_immutable_source_and_metadata():
    db = sqlite3.connect(":memory:")
    store = OnchainTargetStore(db)
    record = _record()

    target_id = store.put(record)
    restored = store.get(target_id)

    assert target_id == record.target_id
    assert restored == record
    assert restored.source_files == record.source_files
    assert restored.runtime_code_sha256 == "c" * 64
    assert restored.block_hash == "0x" + "b" * 64


def test_store_put_is_idempotent_for_identical_target():
    store = OnchainTargetStore(sqlite3.connect(":memory:"))
    record = _record()

    assert store.put(record) == store.put(record)
    assert store.count() == 1


def test_store_rejects_different_source_for_same_chain_address_block():
    store = OnchainTargetStore(sqlite3.connect(":memory:"))
    original = _record()
    store.put(original)
    conflicting = _record(source_files={"src/Vault.sol": "contract Changed {}"})

    with pytest.raises(OnchainTargetError, match="onchain_target_immutable_conflict"):
        store.put(conflicting)


def test_store_allows_new_block_for_same_contract():
    store = OnchainTargetStore(sqlite3.connect(":memory:"))
    first = _record()
    second = _record(
        block_number=123457,
        block_hash="0x" + "d" * 64,
        runtime_code_sha256="e" * 64,
    )

    store.put(first)
    store.put(second)

    assert store.count() == 2
    assert store.get(second.target_id) == second
    assert store.find_latest(8453, first.address) == second


def test_store_rejects_non_record_values():
    store = OnchainTargetStore(sqlite3.connect(":memory:"))
    with pytest.raises(OnchainTargetError, match="onchain_target_record_required"):
        store.put({"chain_id": 8453})
