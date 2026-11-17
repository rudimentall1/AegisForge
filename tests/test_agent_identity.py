import pytest

from shared.agent_identity import AgentIdentity, AgentIdentityError


def test_worker_identity_is_stable_for_same_role_and_host():
    first = AgentIdentity.for_worker("developer", "host-a")
    second = AgentIdentity.for_worker("developer", "host-a")
    assert first == second
    assert first.agent_id.startswith("af-")
    assert first.role == "developer"


def test_worker_identity_differs_by_role():
    developer = AgentIdentity.for_worker("developer", "host-a")
    validator = AgentIdentity.for_worker("validator", "host-a")
    assert developer.agent_id != validator.agent_id


def test_identity_is_immutable():
    identity = AgentIdentity.for_worker("developer", "host-a")
    with pytest.raises(Exception):
        identity.agent_id = "forged"


def test_missing_identity_fields_fail_closed():
    with pytest.raises(AgentIdentityError, match="agent_id_required"):
        AgentIdentity(agent_id="", role="developer")
