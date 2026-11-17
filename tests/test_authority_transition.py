import pytest

from shared.authority_transition import AuthorityTransitionPolicy, AuthorityTransitionPolicyError


def test_default_policy_requires_governance_for_elevated():
    policy = AuthorityTransitionPolicy()
    assert policy.can_governance_promote_elevated(3, 0) is True
    assert policy.can_governance_promote_elevated(3, 1) is False


def test_invalid_policy_thresholds_fail_closed():
    with pytest.raises(AuthorityTransitionPolicyError, match="invalid_trusted_threshold"):
        AuthorityTransitionPolicy(min_trusted_outcomes_for_elevated=0)
    with pytest.raises(AuthorityTransitionPolicyError, match="invalid_failed_threshold"):
        AuthorityTransitionPolicy(max_failed_outcomes_for_elevated=-1)
