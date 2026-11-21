import hashlib
import json
import sqlite3

import pytest

from shared.onchain_target_store import OnchainTargetRecord, OnchainTargetStore
from shared.onchain_verification_store import (
    OnchainVerificationError,
    OnchainVerificationRecord,
    OnchainVerificationStore,
)


def _target(db):
    source_path = "src/Vault.sol"
    source = "pragma solidity 0.8.24; contract Vault {}"
    standard_input = json.dumps({
        "language": "Solidity",
        "sources": {source_path: {"content": source}},
        "settings": {
            "outputSelection": {"*": {"*": ["evm.deployedBytecode.object"]}},
        },
    }, sort_keys=True, separators=(",", ":"))
    runtime = "0x6001600055"
    runtime_digest = hashlib.sha256(bytes.fromhex(runtime[2:])).hexdigest()
    target = OnchainTargetRecord(
        chain_id=31337,
        address="0x" + "1" * 40,
        block_number=12,
        block_hash="0x" + "2" * 64,
        runtime_code_sha256=runtime_digest,
        runtime_code=runtime,
        source_files={source_path: source},
        source_provider="unit-test",
        compiler_version="0.8.24+commit.e11b9ed9",
        contract_name="Vault",
        standard_json_input=standard_input,
    )
    store = OnchainTargetStore(db)
    store.put(target)
    return store, target


def _verified(target, **overrides):
    values = {
        "status": "VERIFIED",
        "reason": "runtime_bytecode_exact_match",
        "compiler_version": "0.8.24+commit.e11b9ed9",
        "compiler_binary_sha256": "a" * 64,
        "compiled_runtime_sha256": target.runtime_code_sha256,
        "compiler_image": "ghcr.io/foundry-rs/foundry@sha256:" + "b" * 64,
        "isolation": "container",
    }
    values.update(overrides)
    return OnchainVerificationRecord.from_target(target, **values)


def test_verification_store_persists_evidence_bound_to_exact_target_and_block():
    db = sqlite3.connect(":memory:")
    targets, target = _target(db)
    verifications = OnchainVerificationStore(targets)

    record = _verified(target)
    verification_id = verifications.put(record)
    persisted = verifications.get(verification_id)

    assert persisted == record
    assert persisted.target_id == target.target_id
    assert persisted.block_hash == target.block_hash
    assert persisted.deployed_runtime_sha256 == target.runtime_code_sha256
    assert verifications.list_for_target(target.target_id) == [record]


def test_verification_store_is_idempotent_for_identical_evidence():
    db = sqlite3.connect(":memory:")
    targets, target = _target(db)
    verifications = OnchainVerificationStore(targets)
    record = _verified(target)

    first = verifications.put(record)
    second = verifications.put(record)

    assert first == second
    assert verifications.count() == 1


def test_verification_store_rejects_evidence_for_missing_target():
    db = sqlite3.connect(":memory:")
    targets, target = _target(db)
    verifications = OnchainVerificationStore(targets)
    record = _verified(target)
    db.execute("DELETE FROM onchain_targets WHERE target_id = ?", (target.target_id,))
    db.commit()

    with pytest.raises(OnchainVerificationError, match="verification_target_missing"):
        verifications.put(record)


def test_verification_store_rejects_target_coordinate_or_digest_drift():
    db = sqlite3.connect(":memory:")
    targets, target = _target(db)
    verifications = OnchainVerificationStore(targets)
    record = _verified(target)
    altered = OnchainVerificationRecord(
        target_id=record.target_id,
        chain_id=record.chain_id,
        address=record.address,
        block_number=record.block_number,
        block_hash="0x" + "3" * 64,
        source_sha256=record.source_sha256,
        standard_json_input_sha256=record.standard_json_input_sha256,
        compiler_version=record.compiler_version,
        compiler_binary_sha256=record.compiler_binary_sha256,
        compiled_runtime_sha256=record.compiled_runtime_sha256,
        deployed_runtime_sha256=record.deployed_runtime_sha256,
        status=record.status,
        reason=record.reason,
        compiler_image=record.compiler_image,
        isolation=record.isolation,
    )

    with pytest.raises(OnchainVerificationError, match="verification_target_binding_mismatch"):
        verifications.put(altered)


def test_verified_record_requires_complete_compiler_and_runtime_evidence():
    db = sqlite3.connect(":memory:")
    targets, target = _target(db)
    with pytest.raises(OnchainVerificationError, match="verified_compiler_evidence_incomplete"):
        OnchainVerificationRecord.from_target(
            target,
            status="VERIFIED",
            reason="runtime_bytecode_exact_match",
            compiler_version="",
            compiler_binary_sha256="",
            compiled_runtime_sha256="",
            compiler_image="",
            isolation="",
        )


def test_mismatch_record_requires_different_compiled_and_deployed_runtime_digests():
    db = sqlite3.connect(":memory:")
    targets, target = _target(db)
    with pytest.raises(OnchainVerificationError, match="mismatch_runtime_digests_equal"):
        _verified(
            target,
            status="MISMATCH",
            reason="runtime_bytecode_mismatch",
            compiled_runtime_sha256=target.runtime_code_sha256,
        )


def test_incomplete_verification_can_be_persisted_without_compiler_binary():
    db = sqlite3.connect(":memory:")
    targets, target = _target(db)
    verifications = OnchainVerificationStore(targets)
    record = OnchainVerificationRecord.from_target(
        target,
        status="INCOMPLETE",
        reason="compiler_compiler_unavailable:required_solc_binary_not_installed",
    )

    verification_id = verifications.put(record)

    assert verifications.get(verification_id).status == "INCOMPLETE"


def test_verification_rows_cannot_be_updated_or_deleted():
    db = sqlite3.connect(":memory:")
    targets, target = _target(db)
    verifications = OnchainVerificationStore(targets)
    verification_id = verifications.put(_verified(target))

    with pytest.raises(sqlite3.IntegrityError, match="onchain_verification_immutable"):
        db.execute(
            "UPDATE onchain_verifications SET reason = ? WHERE verification_id = ?",
            ("rewritten", verification_id),
        )
    with pytest.raises(sqlite3.IntegrityError, match="onchain_verification_immutable"):
        db.execute(
            "DELETE FROM onchain_verifications WHERE verification_id = ?",
            (verification_id,),
        )
