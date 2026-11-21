import hashlib
import json

import pytest

from shared.onchain_research_case import (
    OnchainResearchCase,
    OnchainResearchCaseError,
    onchain_case_binding,
    verify_onchain_case_binding,
    validate_onchain_task_binding,
)


def valid_case(**overrides):
    values = {
        "case_id": "base-vault-review-001",
        "target_id": "a" * 64,
        "scope_url": "https://immunefi.com/bug-bounty/example/scope/",
        "scope_digest": "b" * 64,
        "scope_reviewed_on": "2026-11-21",
        "authorization_reference": "https://immunefi.com/bug-bounty/example/",
        "hypothesis": "A public entry point may violate the accounting invariant.",
        "expected_invariant": "Total liabilities never exceed assets.",
        "falsification_criteria": "Counterexamples fail under independent source review.",
    }
    values.update(overrides)
    return OnchainResearchCase(**values)


def test_valid_onchain_case_is_immutable_and_binds_target():
    case = valid_case()
    assert case.target_id == "a" * 64
    with pytest.raises((AttributeError, TypeError)):
        case.target_id = "c" * 64


@pytest.mark.parametrize("field,value", [
    ("target_id", "not-a-target"),
    ("scope_digest", "x" * 64),
    ("scope_url", "http://example.com/scope"),
    ("authorization_reference", "javascript:alert(1)"),
    ("scope_reviewed_on", "yesterday"),
])
def test_invalid_scope_or_target_evidence_is_rejected(field, value):
    with pytest.raises(OnchainResearchCaseError):
        valid_case(**{field: value})


def test_onchain_case_rejects_runtime_or_unapproved_techniques():
    with pytest.raises(OnchainResearchCaseError, match="technique_not_allowed"):
        valid_case(allowed_techniques=("runtime_probe",))


def test_binding_round_trip_and_tamper_detection():
    binding = onchain_case_binding(valid_case())
    restored = verify_onchain_case_binding(binding)
    assert restored == valid_case()
    binding["case"]["hypothesis"] = "tampered"
    with pytest.raises(OnchainResearchCaseError, match="digest_mismatch"):
        verify_onchain_case_binding(binding)


def test_binding_rejects_tampered_payload_even_with_recomputed_digest():
    binding = onchain_case_binding(valid_case())
    binding["case"]["target_id"] = "z" * 64
    canonical = json.dumps(binding["case"], sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    binding["case_digest"] = hashlib.sha256(canonical.encode()).hexdigest()
    with pytest.raises(OnchainResearchCaseError, match="payload_invalid"):
        verify_onchain_case_binding(binding)


def test_task_binding_requires_matching_registered_case():
    case = valid_case()
    assert validate_onchain_task_binding(case, case.case_id) is case
    with pytest.raises(OnchainResearchCaseError, match="not_registered"):
        validate_onchain_task_binding(None, case.case_id)
    with pytest.raises(OnchainResearchCaseError, match="mismatch"):
        validate_onchain_task_binding(case, "other-case")


def _register_target(queue):
    from shared.onchain_target_store import OnchainTargetRecord, OnchainTargetStore
    record = OnchainTargetRecord(
        chain_id=8453,
        address="0x" + "1" * 40,
        block_number=123,
        block_hash="0x" + "2" * 64,
        runtime_code_sha256="3" * 64,
        source_files={"src/Vault.sol": "contract Vault { function withdraw() external {} }"},
        source_provider="blockscout_v2",
        compiler_version="0.8.24",
        contract_name="Vault",
    )
    store = OnchainTargetStore(queue.db)
    store.put(record)
    return record


def test_queue_registers_case_only_for_persisted_target(tmp_path):
    from shared.queue import TaskQueue
    queue = TaskQueue(db_path=tmp_path / "onchain.sqlite")
    case = valid_case()
    with pytest.raises(ValueError, match="onchain_target_not_registered"):
        queue.register_onchain_research_case(case)
    target = _register_target(queue)
    case = valid_case(target_id=target.target_id)
    assert queue.register_onchain_research_case(case) == case.case_id
    assert queue.get_onchain_research_case(case.case_id) == case
    assert queue.get_onchain_target(target.target_id).source_files["src/Vault.sol"].startswith("contract Vault")
    queue.db.close()


def test_queue_binds_onchain_case_to_worker_claim(tmp_path):
    from shared.queue import TaskQueue
    queue = TaskQueue(db_path=tmp_path / "onchain.sqlite")
    target = _register_target(queue)
    case = valid_case(target_id=target.target_id)
    queue.register_onchain_research_case(case)
    task_id = queue.add("review acquired Solidity source", role="source_researcher", onchain_case_id=case.case_id)
    claimed = queue.claim("source-worker", role="source_researcher")
    assert claimed[0] == task_id
    assert claimed[12] is None
    assert claimed[13] == case.case_id
    queue.db.close()


def test_onchain_case_binding_inherits_across_child_tasks(tmp_path):
    from shared.queue import TaskQueue
    queue = TaskQueue(db_path=tmp_path / "onchain.sqlite")
    target = _register_target(queue)
    case = valid_case(target_id=target.target_id)
    queue.register_onchain_research_case(case)
    parent = queue.add("source triage", role="source_researcher", onchain_case_id=case.case_id)
    child = queue.add("crypto review", role="crypto_analyst", parent_task_id=parent)
    stored = queue.db.execute(
        "SELECT onchain_case_id FROM queue WHERE id = ?", (child,)
    ).fetchone()
    assert stored == (case.case_id,)
    queue.db.close()


def test_queue_rejects_cross_binding_and_onchain_lab_execution(tmp_path):
    from shared.queue import TaskQueue
    from shared.research_case import ResearchCase
    queue = TaskQueue(db_path=tmp_path / "onchain.sqlite")
    target = _register_target(queue)
    case = valid_case(target_id=target.target_id)
    queue.register_onchain_research_case(case)
    with pytest.raises(ValueError, match="git_research_case_required_for_lab_runner"):
        queue.add("run target", role="lab_runner", onchain_case_id=case.case_id)
    with pytest.raises(ValueError, match="mutually_exclusive"):
        queue.add(
            "mixed provenance",
            role="source_researcher",
            research_case_id="git-case",
            onchain_case_id=case.case_id,
        )
    queue.db.close()


def test_queue_rejects_onchain_child_rebound_to_another_case(tmp_path):
    from shared.queue import TaskQueue
    queue = TaskQueue(db_path=tmp_path / "onchain.sqlite")
    target = _register_target(queue)
    first = valid_case(target_id=target.target_id)
    second = valid_case(case_id="base-vault-review-002", target_id=target.target_id)
    queue.register_onchain_research_case(first)
    queue.register_onchain_research_case(second)
    parent = queue.add("source triage", role="source_researcher", onchain_case_id=first.case_id)
    with pytest.raises(ValueError, match="onchain_case_parent_mismatch"):
        queue.add("cross-case child", role="crypto_analyst", parent_task_id=parent, onchain_case_id=second.case_id)
    queue.db.close()


def test_evidence_observations_inherit_onchain_case_id(tmp_path):
    from shared.evidence_ledger import EvidenceLedger
    from shared.queue import TaskQueue
    queue = TaskQueue(db_path=tmp_path / "onchain-evidence.sqlite")
    target = _register_target(queue)
    case = valid_case(target_id=target.target_id)
    queue.register_onchain_research_case(case)
    task_id = queue.add(
        "review source",
        role="source_researcher",
        onchain_case_id=case.case_id,
    )
    ledger = EvidenceLedger(queue.db)
    ledger.record_observation(task_id, "source_researcher", "source_signal:delegatecall")
    row = queue.db.execute(
        "SELECT case_id FROM evidence_observations WHERE task_id = ?",
        (task_id,),
    ).fetchone()
    assert row == (case.case_id,)
    queue.db.close()


def test_onchain_task_graph_can_chain_independent_security_checker(tmp_path):
    from shared.queue import TaskQueue
    queue = TaskQueue(db_path=tmp_path / "onchain-graph.sqlite")
    target = _register_target(queue)
    case = valid_case(target_id=target.target_id)
    queue.register_onchain_research_case(case)
    source_task = queue.add("source triage", role="source_researcher", onchain_case_id=case.case_id)
    crypto_task = queue.add("crypto analysis", role="crypto_analyst", parent_task_id=source_task)
    security_task = queue.add("independent security review", role="security_checker", parent_task_id=crypto_task)
    rows = [
        queue.db.execute(
            "SELECT onchain_case_id FROM queue WHERE id = ?", (task_id,)
        ).fetchone()
        for task_id in (source_task, crypto_task, security_task)
    ]
    assert rows == [(case.case_id,), (case.case_id,), (case.case_id,)]
    queue.db.close()
