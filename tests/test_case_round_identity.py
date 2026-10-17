import pytest

from shared.case_round_identity import CaseRoundIdentityError, validate_case_round_relationships

CASE, SPEC, RUNTIME, ROOT = "case-1", "spec-source-pattern", "runtime-round-uuid", "root-task"

def _round(**overrides):
    value = {"case_id": CASE, "round_id": RUNTIME, "round_number": 1, "round_spec_id": SPEC, "root_task_id": ROOT, "status": "QUEUED", "created_at": "2026-10-17T00:00:00+00:00", "started_at": None, "finished_at": None}
    value.update(overrides)
    return value

def _root(**overrides):
    value = {"id": ROOT, "research_case_id": CASE, "round_id": RUNTIME, "round_spec_id": SPEC, "parent_task_id": None}
    value.update(overrides)
    return value

def _evidence(**overrides):
    value = {"case_id": CASE, "task_id": ROOT, "round_id": RUNTIME, "round_spec_id": SPEC}
    value.update(overrides)
    return value

def _validate(rounds=None, tasks=None, evidence=None, specs=None):
    return validate_case_round_relationships(case_id=CASE, declared_spec_ids={SPEC} if specs is None else specs, rounds=[_round()] if rounds is None else rounds, tasks=[_root()] if tasks is None else tasks, evidence=[_evidence()] if evidence is None else evidence)

def test_accepts_separate_plan_and_runtime_identities():
    _validate()
    assert SPEC != RUNTIME

@pytest.mark.parametrize(("mutate", "error"), [({"round_spec_id": None}, "planned_round_missing_spec_binding"), ({"round_spec_id": "undeclared"}, "round_spec_not_declared_in_case"), ({"round_id": ""}, "round_round_id_invalid"), ({"round_number": True}, "round_number_invalid"), ({"status": "CONFIRMED"}, "round_status_invalid")])
def test_round_registry_rejects_invalid_or_ambiguous_identity(mutate, error):
    with pytest.raises(CaseRoundIdentityError, match=error):
        _validate(rounds=[_round(**mutate)])

def test_planned_task_cannot_use_spec_id_as_runtime_id():
    with pytest.raises(CaseRoundIdentityError, match="task_runtime_round_not_registered"):
        _validate(tasks=[_root(round_id=SPEC)])

def test_task_spec_binding_must_match_registered_round():
    with pytest.raises(CaseRoundIdentityError, match="task_round_spec_identity_mismatch"):
        _validate(tasks=[_root(round_spec_id="another-spec")])

def test_evidence_cannot_be_swapped_between_runtime_rounds():
    with pytest.raises(CaseRoundIdentityError, match="evidence_runtime_round_identity_mismatch"):
        _validate(evidence=[_evidence(round_id="other-runtime-round")])

def test_evidence_cannot_be_swapped_between_planned_specs():
    with pytest.raises(CaseRoundIdentityError, match="evidence_round_spec_identity_mismatch"):
        _validate(evidence=[_evidence(round_spec_id="another-spec")])

def test_round_registry_requires_root_task_to_match_record():
    with pytest.raises(CaseRoundIdentityError, match="round_root_task_missing"):
        _validate(tasks=[])

def test_planned_case_rejects_unscoped_task():
    with pytest.raises(CaseRoundIdentityError, match="planned_task_missing_runtime_round"):
        _validate(tasks=[_root(round_id=None, round_spec_id=None)])

def test_unplanned_legacy_case_can_be_checked_without_inventing_a_plan():
    _validate(rounds=[], tasks=[_root(round_id=None, round_spec_id=None)], evidence=[_evidence(round_id=None, round_spec_id=None)], specs=set())
