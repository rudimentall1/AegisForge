import pytest

from agents.worker_roles import resolve_worker_role


VALID_ROLES = {
    "researcher",
    "analyst",
    "developer",
    "security_checker",
    "opportunity_hunter",
    "validator",
    "model_researcher",
    "source_researcher",
    "deep_researcher",
    "crypto_analyst",
    "lab_runner",
    "executor",
}


def test_no_argument_keeps_legacy_default():
    assert resolve_worker_role([], VALID_ROLES) == "security_checker"


@pytest.mark.parametrize("role", sorted(VALID_ROLES))
def test_named_role_is_preserved(role):
    assert resolve_worker_role([role], VALID_ROLES) == role


@pytest.mark.parametrize("instance", ["1", "2", "3", "4"])
def test_numeric_systemd_instances_remain_legacy_security_checker_pool(instance):
    assert resolve_worker_role([instance], VALID_ROLES) == "security_checker"


def test_unknown_numeric_systemd_instance_is_rejected():
    with pytest.raises(ValueError, match="unsupported worker role"):
        resolve_worker_role(["5"], VALID_ROLES)


def test_role_is_normalized():
    assert resolve_worker_role(["  ANALYST  "], VALID_ROLES) == "analyst"


def test_unknown_role_is_rejected():
    with pytest.raises(ValueError, match="unsupported worker role"):
        resolve_worker_role(["not-a-role"], VALID_ROLES)


def test_multiple_arguments_are_rejected():
    with pytest.raises(ValueError, match="exactly one worker role"):
        resolve_worker_role(["analyst", "developer"], VALID_ROLES)
