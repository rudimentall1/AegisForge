import pytest

from shared.capability_policy import (
    ActionIntent,
    CapabilityDecision,
    CapabilityPolicy,
)


SAFE_CASES = [
    ("researcher", "research", {"requires_network": True}),
    ("researcher", "read_public_docs", {}),
    ("analyst", "analyze", {}),
    ("analyst", "inspect_evidence", {}),
    ("developer", "inspect_code", {"requires_filesystem": True}),
    ("security_checker", "security_scan", {"requires_filesystem": True}),
    ("security_checker", "inspect_code", {"requires_filesystem": True}),
    ("security_checker", "verify", {}),
    ("opportunity_hunter", "identify_opportunities", {}),
    ("opportunity_hunter", "research", {}),
    ("validator", "validate", {}),
    ("validator", "verify", {}),
    ("model_researcher", "model_research", {"requires_network": True}),
    ("model_researcher", "research", {"requires_network": True}),
]


@pytest.mark.parametrize("role,action,flags", SAFE_CASES)
def test_role_action_matrix_allows_declared_read_only_capabilities(role, action, flags):
    result = CapabilityPolicy().check(
        ActionIntent(role=role, action=action, read_only=True, **flags)
    )
    assert result["decision"] == CapabilityDecision.ALLOW


@pytest.mark.parametrize(
    "role,action",
    [
        ("researcher", "deploy"),
        ("analyst", "delete"),
        ("developer", "research"),
        ("security_checker", "transfer"),
        ("opportunity_hunter", "publish"),
        ("validator", "deploy"),
        ("model_researcher", "delete"),
    ],
)
def test_cross_role_action_escalation_blocks(role, action):
    result = CapabilityPolicy().check(
        ActionIntent(role=role, action=action)
    )
    assert result["decision"] == CapabilityDecision.BLOCK
    assert result["reason"] == "action_not_allowed_for_role"


@pytest.mark.parametrize(
    "action",
    ["modify_code", "deploy", "publish", "delete", "transfer", "release"],
)
def test_sensitive_actions_require_evidence_even_without_sensitive_flags(action):
    result = CapabilityPolicy().check(
        ActionIntent(
            role="developer",
            action=action,
            read_only=True,
        )
    )
    assert result["decision"] == CapabilityDecision.REQUIRE_EVIDENCE
    assert result["reason"] == "evidence_required_for_sensitive_action"


@pytest.mark.parametrize(
    "flags",
    [
        {"irreversible": True},
        {"financial": True},
        {"privileged": True},
        {"evidence_required": True},
        {"read_only": False},
    ],
)
def test_sensitive_properties_require_evidence(flags):
    result = CapabilityPolicy().check(
        ActionIntent(
            role="developer",
            action="run_tests",
            **flags,
        )
    )
    assert result["decision"] == CapabilityDecision.REQUIRE_EVIDENCE


@pytest.mark.parametrize(
    "field,value,expected_reason",
    [
        ("target", "unknown_external_endpoint", "blocked_target"),
        ("target", "production_database", "blocked_target"),
        ("target", "production_environment", "blocked_target"),
        ("destination", "production_database", "blocked_destination"),
        ("destination", "production", "blocked_destination"),
        ("destination", "production_environment", "blocked_destination"),
        ("destination", "production_api", "blocked_destination"),
        (
            "destination",
            "unauthorized_external_destination",
            "blocked_destination",
        ),
        ("data_scope", "credentials", "blocked_data_scope"),
        ("data_scope", "private_keys", "blocked_data_scope"),
        ("data_scope", "secrets", "blocked_data_scope"),
        ("data_scope", "api_keys", "blocked_data_scope"),
        ("data_scope", "passwords", "blocked_data_scope"),
    ],
)
def test_hard_boundary_matrix_blocks_forbidden_resources(field, value, expected_reason):
    kwargs = {"role": "developer", "action": "inspect_code", "read_only": True}
    kwargs[field] = value
    result = CapabilityPolicy().check(ActionIntent(**kwargs))
    assert result["decision"] == CapabilityDecision.BLOCK
    assert result["reason"] == expected_reason


@pytest.mark.parametrize(
    "attribute,action",
    [
        ("shell_allowed", "run_tests"),
        ("network_allowed", "inspect_code"),
        ("filesystem_allowed", "inspect_code"),
    ],
)
def test_environment_capability_disable_is_fail_closed(attribute, action):
    policy = CapabilityPolicy()
    setattr(policy, attribute, False)

    flags = {
        "requires_shell": attribute == "shell_allowed",
        "requires_network": attribute == "network_allowed",
        "requires_filesystem": attribute == "filesystem_allowed",
    }
    result = policy.check(
        ActionIntent(
            role="developer",
            action=action,
            read_only=True,
            **flags,
        )
    )
    assert result["decision"] == CapabilityDecision.BLOCK
    assert result["reason"] in {
        "shell_disabled",
        "network_disabled",
        "filesystem_disabled",
    }


def test_unknown_role_is_fail_closed():
    result = CapabilityPolicy().check(
        ActionIntent(role="unknown_role", action="inspect_code")
    )
    assert result["decision"] == CapabilityDecision.BLOCK
    assert result["reason"] == "action_not_allowed_for_role"


def test_block_precedes_sensitive_evidence_requirement():
    result = CapabilityPolicy().check(
        ActionIntent(
            role="developer",
            action="deploy",
            target="production_environment",
            irreversible=True,
        )
    )
    assert result["decision"] == CapabilityDecision.BLOCK
    assert result["reason"] == "blocked_target"
