from shared.authority_state import AuthorityState
from shared.capability_policy import ActionIntent, CapabilityDecision
from shared.effective_capability import EffectiveCapabilityDecision, evaluate_effective_capability


def intent(action, role="developer", **kwargs):
    return ActionIntent(role=role, action=action, **kwargs)


def test_probation_allows_safe_read_only_action():
    result = evaluate_effective_capability(intent("inspect_code"), AuthorityState.PROBATION)
    assert result.decision == EffectiveCapabilityDecision.ALLOW


def test_probation_blocks_deploy_even_when_static_policy_allows_role():
    result = evaluate_effective_capability(intent("deploy", read_only=False), AuthorityState.PROBATION)
    assert result.decision == EffectiveCapabilityDecision.BLOCK
    assert result.reason == "dynamic_authority_restricted"


def test_limited_blocks_network_action():
    result = evaluate_effective_capability(
        intent("api_request", read_only=False, requires_network=True),
        AuthorityState.LIMITED,
    )
    assert result.decision == EffectiveCapabilityDecision.BLOCK


def test_standard_preserves_static_evidence_requirement():
    result = evaluate_effective_capability(
        intent("deploy", read_only=False),
        AuthorityState.STANDARD,
    )
    assert result.decision == EffectiveCapabilityDecision.REQUIRE_EVIDENCE


def test_elevated_does_not_bypass_static_policy():
    result = evaluate_effective_capability(
        intent("deploy", read_only=False),
        AuthorityState.ELEVATED,
    )
    assert result.decision == EffectiveCapabilityDecision.REQUIRE_EVIDENCE


def test_suspended_blocks_everything():
    result = evaluate_effective_capability(intent("inspect_code"), AuthorityState.SUSPENDED)
    assert result.decision == EffectiveCapabilityDecision.BLOCK


def test_static_policy_block_wins_over_dynamic_state():
    result = evaluate_effective_capability(
        intent("deploy", role="researcher", read_only=False),
        AuthorityState.ELEVATED,
    )
    assert result.decision == EffectiveCapabilityDecision.BLOCK
    assert result.reason.startswith("static_policy:")
