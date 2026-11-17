import pytest

from shared.research_case import CaseValidationError, ResearchCase


def _case(technique, days):
    return ResearchCase(
        case_id="deadline-policy-case",
        target_repository="example/project",
        target_commit="a" * 40,
        scope_url="https://example.com/scope",
        scope_digest="b" * 64,
        scope_reviewed_on="2026-10-16",
        hypothesis="A falsifiable, bounded hypothesis.",
        attacker_capability="An unprivileged caller can reach the public entrypoint.",
        expected_invariant="The state invariant remains true.",
        falsification_criteria="A counter-test preserves the invariant.",
        allowed_techniques=(technique,),
        rounds=[{
            "round_id": "round-policy",
            "technique": technique,
            "hypothesis": "Test the invariant with bounded evidence.",
            "expected_evidence_atoms": ["source reference", "counter-test result"],
            "falsification_criteria": "The counter-test does not reproduce the issue.",
            "priority": 1,
            "disclosure_deadline_days": days,
        }],
    )


def test_source_pattern_deadline_90_is_rejected():
    with pytest.raises(CaseValidationError):
        _case("source_pattern", 90)


@pytest.mark.parametrize("days", [6, 200])
def test_deadlines_outside_global_range_are_rejected(days):
    with pytest.raises(CaseValidationError):
        _case("runtime_probe", days)


@pytest.mark.parametrize(
    "technique", ["source_pattern", "crypto_primitive_analysis", "differential_revision"]
)
def test_short_deadline_techniques_accept_60_days(technique):
    case = _case(technique, 60)
    assert case.rounds[0].disclosure_deadline_days == 60


@pytest.mark.parametrize(
    "technique", ["source_pattern", "crypto_primitive_analysis", "differential_revision"]
)
def test_short_deadline_techniques_reject_61_days(technique):
    with pytest.raises(CaseValidationError):
        _case(technique, 61)


def test_runtime_probe_deadline_30_is_valid():
    case = _case("runtime_probe", 30)
    assert case.rounds[0].technique == "runtime_probe"
    assert case.rounds[0].disclosure_deadline_days == 30
