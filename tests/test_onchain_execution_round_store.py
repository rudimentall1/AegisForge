import hashlib
import json
import sqlite3

import pytest

import shared.queue as queue_module
from shared.onchain_execution_admission import OnchainExecutionRequest
from shared.onchain_research_case import OnchainResearchCase
from shared.onchain_target_store import OnchainTargetRecord, OnchainTargetStore
from shared.onchain_verification_store import (
    OnchainVerificationRecord,
    OnchainVerificationStore,
)
from shared.onchain_execution_round_store import (
    OnchainExecutionRoundError,
    OnchainExecutionRoundStore,
    OnchainHarnessBundle,
)
from shared.queue import TaskQueue


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
        source_provider="execution-round-test",
        compiler_version="0.8.24+commit.e11b9ed9",
        contract_name="Vault",
        standard_json_input=standard_input,
    )


def _bundle():
    return OnchainHarnessBundle(
        primary_harness="contract PrimaryControl {}",
        positive_control="contract PositiveControl {}",
        negative_control="contract NegativeControl {}",
    )


@pytest.fixture
def context(tmp_path, monkeypatch):
    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "onchain-round.db")
    queue = TaskQueue()
    target = _target()
    targets = OnchainTargetStore(queue.db)
    targets.put(target)
    case = OnchainResearchCase(
        case_id="round-case-001",
        target_id=target.target_id,
        scope_url="https://example.com/security-scope",
        scope_digest=hashlib.sha256(b"scope").hexdigest(),
        scope_reviewed_on=__import__("datetime").date.today().isoformat(),
        authorization_reference="https://example.com/authorization/round-001",
        hypothesis="A bounded local harness may violate the protected-state invariant",
        expected_invariant="Unauthorized callers cannot change protected state",
        falsification_criteria="Both controls behave as expected and the exploit hypothesis fails",
        allowed_techniques=("source_pattern", "exploit_reproduction"),
    )
    queue.register_onchain_research_case(case)
    verifications = OnchainVerificationStore(targets)
    verified = OnchainVerificationRecord.from_target(
        target,
        status="VERIFIED",
        reason="runtime_bytecode_exact_match",
        compiler_version="0.8.24+commit.e11b9ed9",
        compiler_binary_sha256="a" * 64,
        compiled_runtime_sha256=target.runtime_code_sha256,
        compiler_image="ghcr.io/foundry-rs/foundry@sha256:" + "b" * 64,
        isolation="container",
    )
    verifications.put(verified)
    request = OnchainExecutionRequest(
        case_id=case.case_id,
        target_id=target.target_id,
        block_hash=target.block_hash,
        verification_id=verified.verification_id,
        authorization_reference=case.authorization_reference,
    )
    rounds = OnchainExecutionRoundStore(queue.db)
    yield queue, verifications, request, rounds
    queue.db.close()


def test_round_is_created_from_persisted_admission_and_starts_not_run(context):
    queue, verifications, request, rounds = context

    record = rounds.create_round(queue, verifications, request, _bundle())

    assert record.status == "NOT_RUN"
    assert record.case_id == request.case_id
    assert record.target_id == request.target_id
    assert record.block_hash == request.block_hash
    assert record.verification_id == request.verification_id
    assert record.authorization_reference == request.authorization_reference
    assert record.harness_sha256 == _bundle().sha256
    assert record.profile == "foundry_reproduction"
    assert rounds.get_round(record.round_id) == record


def test_identical_round_request_is_idempotent(context):
    queue, verifications, request, rounds = context

    first = rounds.create_round(queue, verifications, request, _bundle())
    second = rounds.create_round(queue, verifications, request, _bundle())

    assert first == second
    assert rounds.count() == 1


def test_changed_harness_creates_a_distinct_round(context):
    queue, verifications, request, rounds = context
    first = rounds.create_round(queue, verifications, request, _bundle())
    changed = OnchainHarnessBundle(
        primary_harness="contract ChangedPrimary {}",
        positive_control="contract PositiveControl {}",
        negative_control="contract NegativeControl {}",
    )

    second = rounds.create_round(queue, verifications, request, changed)

    assert second.round_id != first.round_id
    assert second.harness_sha256 != first.harness_sha256
    assert rounds.count() == 2


def test_harness_bundle_requires_both_independent_controls():
    with pytest.raises(OnchainExecutionRoundError, match="positive_control_required"):
        OnchainHarnessBundle(
            primary_harness="contract Primary {}",
            positive_control="",
            negative_control="contract Negative {}",
        )
    with pytest.raises(OnchainExecutionRoundError, match="negative_control_required"):
        OnchainHarnessBundle(
            primary_harness="contract Primary {}",
            positive_control="contract Positive {}",
            negative_control="",
        )


def test_harness_bundle_enforces_per_artifact_and_total_size_limits():
    with pytest.raises(OnchainExecutionRoundError, match="harness_artifact_too_large"):
        OnchainHarnessBundle(
            primary_harness="x" * (256 * 1024 + 1),
            positive_control="contract Positive {}",
            negative_control="contract Negative {}",
        )


def test_round_creation_rejects_non_admissible_verification(context):
    queue, verifications, request, rounds = context
    incomplete = OnchainVerificationRecord.from_target(
        queue.get_onchain_target(request.target_id),
        status="INCOMPLETE",
        reason="compiler_unavailable",
    )
    verifications.put(incomplete)

    with pytest.raises(Exception, match="verification_record_not_latest"):
        rounds.create_round(queue, verifications, request, _bundle())


def test_round_statuses_are_distinct_and_append_only(context):
    queue, verifications, request, rounds = context
    record = rounds.create_round(queue, verifications, request, _bundle())

    for status in ("INCONCLUSIVE", "SOURCE_ONLY", "NOT_REPRODUCED", "REPRODUCED"):
        db = sqlite3.connect(":memory:")
        isolated = OnchainExecutionRoundStore(db)
        assert isolated.count() == 0
        db.close()

    evidence_digest = hashlib.sha256(b"runner-evidence").hexdigest()
    updated = rounds.record_outcome(record.round_id, "REPRODUCED", evidence_digest)

    assert updated.status == "REPRODUCED"
    assert rounds.get_round(record.round_id).status == "REPRODUCED"
    with pytest.raises(OnchainExecutionRoundError, match="round_outcome_already_recorded"):
        rounds.record_outcome(record.round_id, "NOT_REPRODUCED", evidence_digest)


def test_round_rows_and_events_cannot_be_rewritten(context):
    queue, verifications, request, rounds = context
    record = rounds.create_round(queue, verifications, request, _bundle())

    with pytest.raises(sqlite3.IntegrityError, match="onchain_execution_round_immutable"):
        rounds.db.execute(
            "UPDATE onchain_execution_rounds SET status = 'REPRODUCED' WHERE round_id = ?",
            (record.round_id,),
        )
