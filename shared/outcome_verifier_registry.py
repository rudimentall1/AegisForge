from dataclasses import dataclass
from typing import Callable, Dict

from shared.outcome_contract import validate_outcome_contract, OutcomeContractError


class OutcomeVerifierRegistryError(ValueError):
    pass


@dataclass(frozen=True)
class OutcomeVerifierSpec:
    name: str
    contract_type: str
    verifier_id: str
    factory: Callable


class OutcomeVerifierRegistry:
    """Resolve typed outcome contracts to executable independent verifiers.

    The contract is the source of truth for verifier selection. A caller cannot
    choose a verifier by action alone or silently substitute another verifier.
    Registration is explicit and duplicate verifier IDs are rejected.
    """

    def __init__(self):
        self._specs: Dict[str, OutcomeVerifierSpec] = {}

    def register(self, name, contract_type, verifier_id, factory):
        if not name or not contract_type or not verifier_id:
            raise OutcomeVerifierRegistryError("outcome_verifier_identity_required")
        if not callable(factory):
            raise OutcomeVerifierRegistryError("outcome_verifier_factory_required")
        key = str(verifier_id)
        if key in self._specs:
            raise OutcomeVerifierRegistryError("outcome_verifier_already_registered")
        self._specs[key] = OutcomeVerifierSpec(
            name=str(name),
            contract_type=str(contract_type),
            verifier_id=key,
            factory=factory,
        )
        return self._specs[key]

    def resolve(self, contract, action=None):
        try:
            canonical = validate_outcome_contract(contract, action=action)
        except OutcomeContractError as exc:
            raise OutcomeVerifierRegistryError(str(exc)) from exc
        verifier_id = canonical["verifier"]
        spec = self._specs.get(verifier_id)
        if spec is None:
            raise OutcomeVerifierRegistryError("outcome_verifier_not_registered")
        if spec.contract_type != canonical["type"]:
            raise OutcomeVerifierRegistryError("outcome_verifier_contract_type_mismatch")
        return spec, canonical

    def build(self, contract, action=None, **factory_kwargs):
        spec, canonical = self.resolve(contract, action=action)
        try:
            verifier = spec.factory(**factory_kwargs)
        except TypeError as exc:
            raise OutcomeVerifierRegistryError("outcome_verifier_factory_invalid") from exc
        if not callable(getattr(verifier, "verify", None)):
            raise OutcomeVerifierRegistryError("outcome_verifier_invalid")
        return verifier, canonical

    def verify(self, contract, intent, receipt, action=None, **factory_kwargs):
        effective_action = action or getattr(intent, "action", None)
        verifier, canonical = self.build(contract, action=effective_action, **factory_kwargs)
        outcome = verifier.verify(intent, receipt)
        if not isinstance(outcome, dict):
            raise OutcomeVerifierRegistryError("outcome_verifier_invalid_result")
        if outcome.get("verifier") != canonical["verifier"]:
            raise OutcomeVerifierRegistryError("outcome_verifier_result_mismatch")
        if outcome.get("status") != "PROVEN":
            raise OutcomeVerifierRegistryError("outcome_verifier_not_proven")
        return outcome
