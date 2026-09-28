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
            action="execute",
            target="unknown_external_endpoint"
        )
    )

    assert result["decision"] == CapabilityDecision.BLOCK



def test_requires_evidence_for_irreversible():

    policy = CapabilityPolicy()

    result = policy.check(
        ActionIntent(
            role="worker",
            action="deploy",
            irreversible=True
        )
    )

    assert result["decision"] == CapabilityDecision.REQUIRE_EVIDENCE


def test_allows_safe_research_action():
    policy = CapabilityPolicy()
    result = policy.check(
        ActionIntent(
            role="researcher",
            action="read_public_docs",
        )
    )
    assert result["decision"] == CapabilityDecision.ALLOW


def test_blocks_privileged_target_even_when_network_is_allowed():
    policy = CapabilityPolicy()
    result = policy.check(
        ActionIntent(
            role="developer",
            action="call_api",
            target="production_database",
            requires_network=True,
        )
    )
    assert result["decision"] == CapabilityDecision.BLOCK
