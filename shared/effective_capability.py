from dataclasses import dataclass
from enum import Enum

from shared.authority_state import AuthorityState
from shared.capability_policy import CapabilityDecision, CapabilityPolicy


class EffectiveCapabilityError(ValueError):
    pass


class EffectiveCapabilityDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_EVIDENCE = "REQUIRE_EVIDENCE"


@dataclass(frozen=True)
class EffectiveCapability: 
    decision: EffectiveCapabilityDecision
    reason: str
    state: str
    action: str


# Dynamic authority can only narrow the static CapabilityPolicy.
SAFE_ACTIONS = {
    "research",
    "read_public_docs",
    "analyze",
    "inspect_evidence",
    "inspect_code",
    "security_scan",
    "verify",
    "validate",
    "identify_opportunities",
    "model_research",
    "run_tests",
}


def evaluate_effective_capability(intent, state, policy=None):
    if intent is None:
        raise EffectiveCapabilityError("intent_required")
    if not isinstance(state, AuthorityState):
        try:
            state = AuthorityState(str(state))
        except ValueError as exc:
            raise EffectiveCapabilityError("unknown_authority_state") from exc

    policy = policy or CapabilityPolicy()
    base = policy.check(intent)
    if base["decision"] == CapabilityDecision.BLOCK:
        return EffectiveCapability(
            EffectiveCapabilityDecision.BLOCK,
            "static_policy:" + base["reason"],
            state.value,
            intent.action,
        )

    if state == AuthorityState.SUSPENDED:
        return EffectiveCapability(EffectiveCapabilityDecision.BLOCK, "authority_suspended", state.value, intent.action)

    if state in {AuthorityState.PROBATION, AuthorityState.LIMITED}:
        if (intent.action not in SAFE_ACTIONS
                or not intent.read_only
                or intent.irreversible
                or intent.financial
                or intent.privileged
                or intent.requires_network
                or intent.requires_shell
                or intent.requires_filesystem):
            return EffectiveCapability(EffectiveCapabilityDecision.BLOCK, "dynamic_authority_restricted", state.value, intent.action)

    if base["decision"] == CapabilityDecision.REQUIRE_EVIDENCE:
        return EffectiveCapability(EffectiveCapabilityDecision.REQUIRE_EVIDENCE, base["reason"], state.value, intent.action)

    return EffectiveCapability(EffectiveCapabilityDecision.ALLOW, "effective_authority_allowed", state.value, intent.action)
