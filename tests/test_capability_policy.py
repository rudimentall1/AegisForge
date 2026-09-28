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
