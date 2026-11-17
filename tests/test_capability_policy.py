from shared.capability_policy import (
    CapabilityPolicy,
    ActionIntent,
    CapabilityDecision,
)


def test_blocks_unknown_target():
    policy = CapabilityPolicy()
    result = policy.check(
        ActionIntent(
            role="developer",
            action="deploy",
            target="unknown_external_endpoint",
        )
    )
    assert result["decision"] == CapabilityDecision.BLOCK


def test_requires_evidence_for_irreversible():
    policy = CapabilityPolicy()
    result = policy.check(
        ActionIntent(
            role="developer",
            action="deploy",
            irreversible=True,
        )
    )
    assert result["decision"] == CapabilityDecision.REQUIRE_EVIDENCE
    assert result["reason"] == "evidence_required_for_sensitive_action"


def test_allows_safe_research_action():
    policy = CapabilityPolicy()
    result = policy.check(
        ActionIntent(
            role="researcher",
            action="research",
            requires_network=True,
        )
    )
    assert result["decision"] == CapabilityDecision.ALLOW


def test_blocks_privileged_target_even_when_network_is_allowed():
    policy = CapabilityPolicy()
    result = policy.check(
        ActionIntent(
            role="developer",
            action="deploy",
            target="production_database",
            requires_network=True,
        )
    )
    assert result["decision"] == CapabilityDecision.BLOCK


def test_blocks_action_outside_role_scope():
    policy = CapabilityPolicy()
    result = policy.check(
        ActionIntent(
            role="researcher",
            action="deploy",
        )
    )
    assert result["decision"] == CapabilityDecision.BLOCK
    assert result["reason"] == "action_not_allowed_for_role"


def test_financial_and_privileged_actions_require_evidence():
    policy = CapabilityPolicy()
    for intent in (
        ActionIntent(role="developer", action="transfer", financial=True),
        ActionIntent(role="developer", action="deploy", privileged=True),
    ):
        assert policy.check(intent)["decision"] == CapabilityDecision.REQUIRE_EVIDENCE
