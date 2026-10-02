import pytest

from shared.outcome_verifier_registry import OutcomeVerifierRegistry, OutcomeVerifierRegistryError


class FakeVerifier:
    def verify(self, intent, receipt):
        return {"status": "PROVEN", "verifier": "filesystem_independent_v1", "outcome_id": "x"}


def _registry():
    registry = OutcomeVerifierRegistry()
    registry.register("fake", "state_match", "filesystem_independent_v1", lambda **kwargs: FakeVerifier())
    return registry


def _contract():
    return {"type": "state_match", "verifier": "filesystem_independent_v1", "expected_state": "ABSENT"}


def test_registry_resolves_typed_contract():
    spec, canonical = _registry().resolve(_contract(), action="delete")
    assert spec.verifier_id == "filesystem_independent_v1"
    assert canonical["type"] == "state_match"


def test_registry_rejects_unregistered_verifier():
    registry = OutcomeVerifierRegistry()
    with pytest.raises(OutcomeVerifierRegistryError, match="outcome_verifier_not_registered"):
        registry.resolve({"type": "state_match", "verifier": "filesystem_independent_v1", "expected_state": "ABSENT"}, action="delete")


def test_registry_rejects_contract_type_mismatch():
    registry = OutcomeVerifierRegistry()
    registry.register("fake", "artifact_exists", "filesystem_independent_v1", lambda **kwargs: FakeVerifier())
    with pytest.raises(OutcomeVerifierRegistryError, match="contract_type_mismatch"):
        registry.resolve(_contract(), action="delete")


def test_registry_requires_contract_for_transfer():
    registry = OutcomeVerifierRegistry()
    with pytest.raises(OutcomeVerifierRegistryError, match="outcome_contract_required"):
        registry.resolve({}, action="transfer")


def test_registry_rejects_forged_verifier_result():
    class Forged:
        def verify(self, intent, receipt):
            return {"status": "PROVEN", "verifier": "forged_v1", "outcome_id": "x"}
    registry = OutcomeVerifierRegistry()
    registry.register("fake", "state_match", "filesystem_independent_v1", lambda **kwargs: Forged())
    with pytest.raises(OutcomeVerifierRegistryError, match="result_mismatch"):
        registry.verify(_contract(), type("I", (), {"action": "delete"})(), {}, **{})
