from dataclasses import dataclass


SCHEMA_VERSION = "authority-transition-policy-v1"

PROBATION = "PROBATION"
LIMITED = "LIMITED"
STANDARD = "STANDARD"
ELEVATED = "ELEVATED"
SUSPENDED = "SUSPENDED"


class AuthorityTransitionPolicyError(ValueError):
    pass


@dataclass(frozen=True)
class AuthorityTransitionPolicy:
    """Explicit policy for dynamic authority transitions."""

    min_trusted_outcomes_for_elevated: int = 3
    max_failed_outcomes_for_elevated: int = 0
    require_governance_for_elevated: bool = True

    def __post_init__(self):
        if self.min_trusted_outcomes_for_elevated < 1:
            raise AuthorityTransitionPolicyError("invalid_trusted_threshold")
        if self.max_failed_outcomes_for_elevated < 0:
            raise AuthorityTransitionPolicyError("invalid_failed_threshold")

    def evaluate_trusted(self, current_state, trusted_outcomes, failed_outcomes):
        if current_state == SUSPENDED:
            return SUSPENDED, "suspended_requires_governance_reset"
        if current_state == ELEVATED:
            return ELEVATED, "elevated_authority_requires_governance_change"
        return STANDARD, "trusted_attested_outcome"

    def can_governance_promote_elevated(self, trusted_outcomes, failed_outcomes):
        return (
            self.require_governance_for_elevated
            and trusted_outcomes >= self.min_trusted_outcomes_for_elevated
            and failed_outcomes <= self.max_failed_outcomes_for_elevated
        )
