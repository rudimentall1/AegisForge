from datetime import date, timedelta
import hashlib
import json
import sqlite3

import pytest

import shared.queue as queue_module
from shared.onchain_research_case import OnchainResearchCase
from shared.onchain_target_store import OnchainTargetRecord, OnchainTargetStore
from shared.onchain_verification_store import (
    OnchainVerificationRecord,
    OnchainVerificationStore,
)
from shared.queue import TaskQueue
from shared.onchain_execution_admission import (
    OnchainExecutionAdmissionError,
    OnchainExecutionProfile,
    OnchainExecutionRequest,
    admit_onchain_execution,
)


def _target():
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
    return OnchainTargetRecord(
        chain_id=31337,
        address="0x" + "1" * 40,
        block_number=12,
        block_hash="0x" + "2" * 64,
        runtime_code_sha256=hashlib.sha256(bytes.fromhex(runtime[2:])).hexdigest(),
        runtime_code=runtime,
        source_files={source_path: source},
        source_provider="execution-admission-test",
        compiler_version="0.8.24+commit.e11b9ed9",
        contract_name="Vault",
        standard_json_input=standard_input,
    )


def _case(target, *, reviewed_on=None, techniques=("source_pattern", "exploit_reproduction")):
    reviewed_on = reviewed_on or date.today().isoformat()
    return OnchainResearchCase(
        case_id="case-" + reviewed_on + "-" + "-".join(techniques),
        target_id=target.target_id,
        scope_url="https://example.com/security-scope",
        scope_digest=hashlib.sha256(b"reviewed-scope").hexdigest(),
        scope_reviewed_on=reviewed_on,
        authorization_reference="https://example.com/authorization/123",
        hypothesis="A source-backed invariant may be violated by a bounded local reproduction",
        expected_invariant="Unauthorized callers cannot change protected state",
        falsification_criteria="The local harness cannot violate the invariant",
        allowed_techniques=techniques,
    )


def _verified_record(target, *, status="VERIFIED", reason="runtime_bytecode_exact_match"):
    compiled_digest = target.runtime_code_sha256
    if status == "MISMATCH":
        compiled_digest = "f" * 64
        reason = "runtime_bytecode_mismatch"
    return OnchainVerificationRecord.from_target(
        target,
        status=status,
        reason=reason,
        compiler_version="0.8.24+commit.e11b9ed9" if status != "INCOMPLETE" else "",
        compiler_binary_sha256="a" * 64 if status != "INCOMPLETE" else "",
        compiled_runtime_sha256=compiled_digest if status != "INCOMPLETE" else "",
        compiler_image="ghcr.io/foundry-rs/foundry@sha256:" + "b" * 64 if status != "INCOMPLETE" else "",
        isolation="container" if status != "INCOMPLETE" else "",
    )


@pytest.fixture
def admission_context(tmp_path, monkeypatch):
    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "onchain-execution-admission.db")
    queue = TaskQueue()
    target = _target()
    target_store = OnchainTargetStore(queue.db)
    target_store.put(target)
    case = _case(target)
    queue.register_onchain_research_case(case)
    verification_store = OnchainVerificationStore(target_store)
    verified = _verified_record(target)
    verification_store.put(verified)
    yield queue, target_store, target, case, verification_store, verified
    queue.db.close()


def _request(case, target, verification, **overrides):
    values = {
        "case_id": case.case_id,
        "target_id": target.target_id,
        "block_hash": target.block_hash,
        "verification_id": verification.verification_id,
        "authorization_reference": case.authorization_reference,
        "profile": OnchainExecutionProfile.FOUNDRY_REPRODUCTION,
    }
    values.update(overrides)
    return OnchainExecutionRequest(**values)


def test_admission_requires_explicit_scope_authorization_and_latest_verified_evidence(admission_context):
    queue, _, target, case, verification_store, verification = admission_context

    admitted = admit_onchain_execution(
        queue,
        verification_store,
        _request(case, target, verification),
    )

    assert admitted.case.case_id == case.case_id
    assert admitted.target.target_id == target.target_id
    assert admitted.target.block_hash == target.block_hash
    assert admitted.verification.verification_id == verification.verification_id
    assert admitted.profile is OnchainExecutionProfile.FOUNDRY_REPRODUCTION
    assert admitted.execution_assurance == "NOT_RUN"


def test_admission_rejects_incomplete_verification(admission_context):
    queue, _, target, case, verification_store, _ = admission_context
    incomplete = _verified_record(
        target,
        status="INCOMPLETE",
        reason="compiler_compiler_unavailable:required_solc_binary_not_installed",
    )
    verification_store.put(incomplete)

    with pytest.raises(OnchainExecutionAdmissionError, match="verification_status_not_verified:INCOMPLETE"):
        admit_onchain_execution(
            queue,
            verification_store,
            _request(case, target, incomplete),
        )


def test_admission_rejects_old_verified_record_after_new_incomplete_record(admission_context):
    queue, _, target, case, verification_store, verified = admission_context
    incomplete = _verified_record(
        target,
        status="INCOMPLETE",
        reason="compiler_compiler_unavailable:required_solc_binary_not_installed",
    )
    verification_store.put(incomplete)

    with pytest.raises(OnchainExecutionAdmissionError, match="verification_record_not_latest"):
        admit_onchain_execution(
            queue,
            verification_store,
            _request(case, target, verified),
            today=date(2026, 11, 21),
        )


def test_admission_rejects_stale_scope_review(admission_context):
    queue, _, target, case, verification_store, verification = admission_context
    stale_case = _case(target, reviewed_on=(date.today() - timedelta(days=31)).isoformat())
    queue.register_onchain_research_case(stale_case)

    with pytest.raises(OnchainExecutionAdmissionError, match="scope_review_stale"):
        admit_onchain_execution(
            queue,
            verification_store,
            _request(stale_case, target, verification),
            today=date(2026, 11, 21),
        )


def test_admission_rejects_future_scope_review(admission_context):
    queue, _, target, case, verification_store, verification = admission_context
    future_case = _case(target, reviewed_on=(date.today() + timedelta(days=1)).isoformat())
    queue.register_onchain_research_case(future_case)

    with pytest.raises(OnchainExecutionAdmissionError, match="scope_review_in_future"):
        admit_onchain_execution(
            queue,
            verification_store,
            _request(future_case, target, verification),
            today=date(2026, 11, 21),
        )


def test_admission_rejects_case_without_exploit_reproduction_authorization(admission_context):
    queue, _, target, _, verification_store, verification = admission_context
    source_only_case = _case(target, techniques=("source_pattern",))
    queue.register_onchain_research_case(source_only_case)

    with pytest.raises(OnchainExecutionAdmissionError, match="exploit_reproduction_not_authorized"):
        admit_onchain_execution(
            queue,
            verification_store,
            _request(source_only_case, target, verification),
            today=date(2026, 11, 21),
        )


def test_admission_rejects_authorization_reference_substitution(admission_context):
    queue, _, target, case, verification_store, verification = admission_context

    with pytest.raises(OnchainExecutionAdmissionError, match="authorization_reference_mismatch"):
        admit_onchain_execution(
            queue,
            verification_store,
            _request(
                case,
                target,
                verification,
                authorization_reference="https://example.com/other-authorization",
            ),
            today=date(2026, 11, 21),
        )


def test_admission_rejects_block_hash_substitution(admission_context):
    queue, _, target, case, verification_store, verification = admission_context

    with pytest.raises(OnchainExecutionAdmissionError, match="request_block_hash_mismatch"):
        admit_onchain_execution(
            queue,
            verification_store,
            _request(case, target, verification, block_hash="0x" + "3" * 64),
            today=date(2026, 11, 21),
        )


def test_admission_rejects_untyped_request(admission_context):
    queue, _, _, _, verification_store, _ = admission_context

    with pytest.raises(OnchainExecutionAdmissionError, match="typed_request_required"):
        admit_onchain_execution(queue, verification_store, {}, today=date(2026, 11, 21))


def test_admission_rejects_verification_store_on_different_database(admission_context):
    queue, _, target, case, _, verification = admission_context
    other_db = sqlite3.connect(":memory:")
    other_target_store = OnchainTargetStore(other_db)
    other_target_store.put(target)
    other_verifications = OnchainVerificationStore(other_target_store)
    other_verifications.put(verification)

    with pytest.raises(OnchainExecutionAdmissionError, match="shared_database_connection_required"):
        admit_onchain_execution(
            queue,
            other_verifications,
            _request(case, target, verification),
            today=date(2026, 11, 21),
        )
    other_db.close()
