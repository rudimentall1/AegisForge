import hashlib

import pytest

import shared.queue as queue_module
from shared.case_rounds import start_case_round
from shared.queue import TaskQueue
from shared.research_case import ExecutionMode, ResearchCase, RoundSpec
from shared.target_execution_admission import (
    AdapterProfile,
    TargetExecutionAdmissionError,
    TargetExecutionRequest,
    admit_target_execution,
)


@pytest.fixture
def queue(tmp_path, monkeypatch):
    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "admission.db")
    value = TaskQueue()
    yield value
    value.db.close()


def make_case(*, planned=False):
    rounds = ()
    if planned:
        rounds = (
            RoundSpec(
                round_id="planned-solidity-test",
                technique="source_pattern",
                hypothesis="A bounded synthetic Solidity hypothesis",
                expected_evidence_atoms=("source-pattern-present",),
                falsification_criteria="The pinned source does not contain the pattern",
                priority=1,
                disclosure_deadline_days=30,
            ),
        )
    return ResearchCase(
        case_id="admission-case",
        target_repository="owner/repository",
        target_commit="a" * 40,
        scope_url="https://example.com/scope",
        scope_digest=hashlib.sha256(b"scope").hexdigest(),
        scope_reviewed_on="2026-11-01",
        hypothesis="A bounded synthetic hypothesis",
        attacker_capability="Local test fixture only",
        expected_invariant="The fixture preserves the invariant",
        falsification_criteria="Reject if the invariant changes",
        execution_mode=ExecutionMode.LOCAL,
        rounds=rounds,
    )


def make_running_lab_task(queue, *, planned=False):
    case = make_case(planned=planned)
    queue.register_research_case(case)
    spec_id = case.rounds[0].round_id if case.rounds else None
    started = start_case_round(queue, case.case_id, spec_id)
    child_id = queue.add(
        "bounded local adapter task",
        role="lab_runner",
        parent_task_id=started["root_task_id"],
    )
    queue.db.execute(
        "UPDATE queue SET status='completed', result='{}', finished_at='2026-11-14T00:00:00+00:00' WHERE id=?",
        (started["root_task_id"],),
    )
    queue.db.commit()
    claimed = queue.claim("admission-test-worker", role="lab_runner")
    assert claimed[0] == child_id
    return case, started, child_id


def test_admission_resolves_target_only_from_registered_case(queue):
    case, started, task_id = make_running_lab_task(queue, planned=True)

    admitted = admit_target_execution(
        queue,
        TargetExecutionRequest(task_id, AdapterProfile.FOUNDRY_TEST),
    )

    assert admitted.task_id == task_id
    assert admitted.case_id == case.case_id
    assert admitted.round_id == started["round_id"]
    assert admitted.round_spec_id == case.rounds[0].round_id
    assert admitted.research_case.target_repository == case.target_repository
    assert admitted.research_case.target_commit == case.target_commit
    assert admitted.round_spec is case.rounds[0]
    assert admitted.execution_assurance == "NOT_RUN"


def test_admission_rejects_task_before_it_is_claimed(queue):
    case = make_case()
    queue.register_research_case(case)
    started = start_case_round(queue, case.case_id)

    with pytest.raises(TargetExecutionAdmissionError, match="task_not_running"):
        admit_target_execution(
            queue,
            TargetExecutionRequest(started["root_task_id"], AdapterProfile.SLITHER_STATIC),
        )


def test_admission_rejects_non_lab_runner_role(queue):
    case, started, _ = make_running_lab_task(queue)
    root_id = started["root_task_id"]
    queue.db.execute(
        "UPDATE queue SET status='running', role='source_researcher' WHERE id=?",
        (root_id,),
    )
    queue.db.commit()

    with pytest.raises(TargetExecutionAdmissionError, match="task_role_not_lab_runner"):
        admit_target_execution(
            queue,
            TargetExecutionRequest(root_id, AdapterProfile.FOUNDRY_TEST),
        )


def test_admission_rejects_unregistered_runtime_round(queue):
    _, _, task_id = make_running_lab_task(queue)
    queue.db.execute(
        "UPDATE queue SET round_id='forged-runtime-round' WHERE id=?",
        (task_id,),
    )
    queue.db.commit()

    with pytest.raises(TargetExecutionAdmissionError, match="runtime_round_not_registered"):
        admit_target_execution(
            queue,
            TargetExecutionRequest(task_id, AdapterProfile.SLITHER_STATIC),
        )


def test_admission_rejects_round_spec_registry_mismatch(queue):
    _, _, task_id = make_running_lab_task(queue, planned=True)
    queue.db.execute(
        "UPDATE queue SET round_spec_id='forged-planned-step' WHERE id=?",
        (task_id,),
    )
    queue.db.commit()

    with pytest.raises(TargetExecutionAdmissionError, match="round_spec_not_declared"):
        admit_target_execution(
            queue,
            TargetExecutionRequest(task_id, AdapterProfile.FOUNDRY_TEST),
        )


def test_admission_rejects_untyped_request_and_unknown_profile(queue):
    with pytest.raises(TargetExecutionAdmissionError, match="typed_request_required"):
        admit_target_execution(queue, {"task_id": "arbitrary", "argv": ["sh", "-c", "id"]})

    _, _, task_id = make_running_lab_task(queue)
    with pytest.raises(TargetExecutionAdmissionError, match="adapter_profile_not_allowed"):
        admit_target_execution(queue, TargetExecutionRequest(task_id, "arbitrary-shell"))
