import pytest

from shared.queue import TaskQueue
from shared.evidence_ledger import EvidenceLedger
from shared.research_case import (
    CaseStatus,
    CaseValidationError,
    ExecutionMode,
    ResearchCase,
    validate_task_binding,
    validate_worker_case_binding,
)


def valid_case(**overrides):
    values = dict(
        case_id="ssv-eb-001",
        target_repository="ssvlabs/ssv-network",
        target_commit="a" * 40,
        scope_url="https://immunefi.com/bug-bounty/ssvnetwork/scope/",
        scope_digest="b" * 64,
        scope_reviewed_on="2026-10-15",
        hypothesis="Operator migration can mis-account effective balance.",
        attacker_capability="An unprivileged participant can trigger the permitted state transition.",
        expected_invariant="Accounted value equals independently computed value.",
        falsification_criteria="The same state sequence preserves accounting under counter-tests.",
        execution_mode=ExecutionMode.LOCAL,
        status=CaseStatus.READY,
    )
    values.update(overrides)
    return ResearchCase(**values)


def test_valid_case_allows_matching_task():
    case = valid_case()
    assert validate_task_binding(case, case.case_id) is case


@pytest.mark.parametrize("field,value", [
    ("scope_url", ""),
    ("scope_digest", ""),
    ("scope_reviewed_on", ""),
])
def test_missing_scope_evidence_fails_closed(field, value):
    with pytest.raises(CaseValidationError):
        valid_case(**{field: value})


@pytest.mark.parametrize("commit", ["main", "mainnet-v2.0.0", "a" * 39, "g" * 40])
def test_mutable_or_invalid_source_revision_is_rejected(commit):
    with pytest.raises(CaseValidationError):
        valid_case(target_commit=commit)


def test_missing_case_blocks_task():
    with pytest.raises(CaseValidationError, match="no research case"):
        validate_task_binding(None, "ssv-eb-001")


def test_mismatched_case_id_blocks_task():
    with pytest.raises(CaseValidationError, match="mismatch"):
        validate_task_binding(valid_case(), "different-case")


@pytest.mark.parametrize("mode", ["mainnet", "live", "production"])
def test_prohibited_execution_mode_is_rejected(mode):
    with pytest.raises(CaseValidationError):
        valid_case(execution_mode=mode)


@pytest.mark.parametrize("status", [
    CaseStatus.DRAFT,
    CaseStatus.CONFIRMED,
    CaseStatus.REJECTED,
    CaseStatus.INCONCLUSIVE,
    CaseStatus.OUT_OF_SCOPE,
])
def test_non_executable_case_status_blocks_task(status):
    case = valid_case(status=status)
    with pytest.raises(CaseValidationError, match="does not permit execution"):
        validate_task_binding(case, case.case_id)


def test_case_is_immutable():
    case = valid_case()
    with pytest.raises((AttributeError, TypeError)):
        case.case_id = "changed"


def test_queue_requires_registered_case_for_case_bound_task(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    with pytest.raises(ValueError, match="not_registered"):
        queue.add("run security hypothesis", research_case_id="ssv-eb-001")


def test_queue_persists_case_and_binds_task_to_it(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    case = valid_case()
    queue.register_research_case(case)

    task_id = queue.add("run security hypothesis", research_case_id=case.case_id)
    row = queue.db.execute(
        "SELECT research_case_id FROM queue WHERE id = ?", (task_id,)
    ).fetchone()

    assert row == (case.case_id,)
    assert queue.get_research_case(case.case_id) == case


def test_queue_rejects_reusing_case_id_for_different_scope(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    queue.register_research_case(valid_case())

    with pytest.raises(ValueError, match="different_content"):
        queue.register_research_case(valid_case(scope_digest="c" * 64))


def test_scope_review_date_must_be_iso_date():
    with pytest.raises(CaseValidationError, match="ISO date"):
        valid_case(scope_reviewed_on="yesterday")


def test_evidence_observation_inherits_case_id_from_queued_task(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    case = valid_case()
    queue.register_research_case(case)
    task_id = queue.add("research task", research_case_id=case.case_id)

    ledger = EvidenceLedger(queue.db)
    ledger.record_observation(task_id, "analyst", "hypothesis:counterexample checked")
    stored = queue.db.execute(
        "SELECT case_id FROM evidence_observations WHERE task_id = ?", (task_id,)
    ).fetchone()

    assert stored == (case.case_id,)


def test_claimed_task_carries_case_id_for_worker_gate(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    case = valid_case()
    queue.register_research_case(case)
    queue.add("research task", role="analyst", research_case_id=case.case_id)

    claimed = queue.claim("test-worker", role="analyst")

    assert claimed is not None
    assert claimed[0]
    assert claimed[12] == case.case_id


@pytest.mark.parametrize("role", ["source_researcher", "crypto_analyst", "lab_runner"])
def test_forensic_worker_roles_fail_closed_without_case(role):
    with pytest.raises(CaseValidationError, match="requires a registered research case"):
        validate_worker_case_binding(role, None, None)


def test_generic_worker_role_can_process_legacy_task_without_case():
    assert validate_worker_case_binding("analyst", None, None) is None


def test_forensic_worker_role_accepts_matching_registered_case():
    case = valid_case()
    assert validate_worker_case_binding("crypto_analyst", case, case.case_id) is case


def test_child_task_inherits_parent_research_case(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    case = valid_case()
    queue.register_research_case(case)
    parent_id = queue.add("forensic parent", role="source_researcher",
                          research_case_id=case.case_id)
    child_id = queue.add("forensic child", role="crypto_analyst",
                         parent_task_id=parent_id)
    stored = queue.db.execute(
        "SELECT research_case_id FROM queue WHERE id = ?", (child_id,)
    ).fetchone()
    assert stored == (case.case_id,)
