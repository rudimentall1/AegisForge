import pytest

from shared.research_case import CaseValidationError, ExecutionMode, ResearchCase, RoundSpec
from shared.scope_gate import ALLOWED_TECHNIQUES, GateResult, validate_case


def valid_case():
    return ResearchCase(
        case_id="local-fixture-001",
        target_repository="example/educational-contract",
        target_commit="a" * 40,
        scope_url="https://example.invalid/authorized-lab-scope",
        scope_digest="b" * 64,
        scope_reviewed_on="2026-10-15",
        hypothesis="The fixture violates its documented invariant.",
        attacker_capability="Unprivileged local test caller.",
        expected_invariant="Only the owner can change the protected value.",
        falsification_criteria="Counter-test proves unauthorized mutation is impossible.",
        execution_mode=ExecutionMode.LOCAL,
    )


def bypass_frozen_validation(case, **changes):
    """Simulate corrupted/deserialized state crossing the gate boundary."""
    for field, value in changes.items():
        object.__setattr__(case, field, value)
    return case


def test_valid_local_case_passes_gate():
    result = validate_case(valid_case())
    assert result == GateResult(True, "case_scope_envelope_valid")
    assert result.status == "ALLOW"


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"target_commit": "not-a-commit-sha"}, "target_commit_invalid"),
        ({"target_commit": "g" * 40}, "target_commit_invalid"),
        ({"target_repository": "not-a-repository"}, "target_repository_invalid"),
        ({"scope_digest": "not-a-sha256-digest"}, "scope_digest_invalid"),
        ({"scope_digest": "z" * 64}, "scope_digest_invalid"),
        ({"scope_url": ""}, "scope_reference_missing"),
        ({"scope_url": "http://example.invalid/scope"}, "scope_reference_invalid"),
        ({"scope_reviewed_on": "yesterday"}, "scope_review_date_invalid"),
        ({"scope_reviewed_on": "2026-02-30"}, "scope_review_date_invalid"),
        ({"execution_mode": "mainnet"}, "execution_mode_not_allowed"),
    ],
)
def test_malformed_but_present_scope_fields_fail_closed(changes, reason):
    case = bypass_frozen_validation(valid_case(), **changes)
    result = validate_case(case)
    assert not result.allowed
    assert result.status == "FAIL"
    assert result.reason == reason




@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("hypothesis", "hypothesis_missing"),
        ("attacker_capability", "attacker_capability_missing"),
        ("expected_invariant", "expected_invariant_missing"),
        ("falsification_criteria", "falsification_criteria_missing"),
    ],
)
def test_gate_revalidates_required_case_fields_after_construction(field, reason):
    case = bypass_frozen_validation(valid_case(), **{field: ""})
    result = validate_case(case)
    assert result.status == "FAIL"
    assert result.reason == reason


def test_missing_case_fails_closed():
    result = validate_case(None)
    assert not result.allowed
    assert result.status == "FAIL"
    assert result.reason == "research_case_required"


def test_missing_required_scope_digest_fails_closed():
    case = bypass_frozen_validation(valid_case(), scope_digest="")
    result = validate_case(case)
    assert result.status == "FAIL"
    assert result.reason == "scope_digest_invalid"


def test_invalid_research_result_cannot_be_emitted_by_gate():
    result = validate_case(None)
    assert result.status not in {"CONFIRMED", "REJECTED"}
    assert result.reason == "research_case_required"


def test_gate_does_not_treat_unrecognized_execution_mode_as_allowed():
    case = valid_case()
    bypass_frozen_validation(case, execution_mode=object())
    result = validate_case(case)
    assert result.status == "FAIL"
    assert result.reason == "execution_mode_not_allowed"


def test_research_case_constructor_still_rejects_bad_commit():
    with pytest.raises(CaseValidationError):
        ResearchCase(
            case_id="bad",
            target_repository="example/repo",
            target_commit="not-a-commit-sha",
            scope_url="https://example.invalid/scope",
            scope_digest="b" * 64,
            scope_reviewed_on="2026-10-15",
            hypothesis="hypothesis",
            attacker_capability="local caller",
            expected_invariant="invariant",
            falsification_criteria="counter-test",
        )


def test_scope_review_date_in_future_fails_closed():
    case = bypass_frozen_validation(valid_case(), scope_reviewed_on="2027-01-01")
    result = validate_case(case)
    assert result.status == "FAIL"
    assert result.reason == "scope_review_date_in_future"


def test_implausibly_old_scope_review_date_fails_closed():
    case = bypass_frozen_validation(valid_case(), scope_reviewed_on="2019-12-31")
    result = validate_case(case)
    assert result.status == "FAIL"
    assert result.reason == "scope_review_date_implausible"


def test_research_case_constructor_rejects_unknown_technique():
    with pytest.raises(CaseValidationError, match="technique_not_allowed:made_up"):
        ResearchCase(
            case_id="bad-technique",
            target_repository="example/repo",
            target_commit="a" * 40,
            scope_url="https://example.invalid/scope",
            scope_digest="b" * 64,
            scope_reviewed_on="2026-10-15",
            hypothesis="hypothesis",
            attacker_capability="local caller",
            expected_invariant="invariant",
            falsification_criteria="counter-test",
            allowed_techniques=("made_up",),
        )


def test_scope_gate_technique_allowlist_matches_round_registry():
    from shared.techniques.registry import TechniqueRegistry

    assert ALLOWED_TECHNIQUES == TechniqueRegistry().names


def test_scope_gate_rejects_corrupted_round_technique():
    case = ResearchCase(
        case_id="local-round-001",
        target_repository="example/educational-contract",
        target_commit="a" * 40,
        scope_url="https://example.invalid/authorized-lab-scope",
        scope_digest="b" * 64,
        scope_reviewed_on="2026-10-15",
        hypothesis="Hypothesis.",
        attacker_capability="Synthetic caller.",
        expected_invariant="Only the owner can mutate.",
        falsification_criteria="Counter-test.",
        allowed_techniques=("source_pattern",),
        rounds=(RoundSpec(
            round_id="round-1",
            technique="source_pattern",
            hypothesis="Check access control.",
            expected_evidence_atoms=("pinned source",),
            falsification_criteria="Source identity mismatch.",
            disclosure_deadline_days=30,
        ),),
    )
    object.__setattr__(case.rounds[0], "technique", "made_up")
    result = validate_case(case)
    assert result.status == "FAIL"
    assert result.reason == "technique_not_allowed:made_up"


@pytest.mark.parametrize("rounds", [None, ["not-a-round"], (object(),)])
def test_scope_gate_rejects_corrupted_round_container(rounds):
    case = bypass_frozen_validation(valid_case(), rounds=rounds)
    result = validate_case(case)
    assert result.status == "FAIL"
    assert result.reason in {"rounds_invalid", "round_spec_invalid"}
