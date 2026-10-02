from dataclasses import dataclass
from enum import Enum


SCHEMA_VERSION = "authority-state-v1"


class AuthorityState(str, Enum):
    PROBATION = "PROBATION"
    LIMITED = "LIMITED"
    STANDARD = "STANDARD"
    ELEVATED = "ELEVATED"
    SUSPENDED = "SUSPENDED"


class AuthorityStateError(ValueError):
    pass


@dataclass(frozen=True)
class AuthorityTransition:
    previous_state: str
    new_state: str
    reason: str
    proof_id: str = ""
    agent_id: str = ""

    def to_dict(self):
        return {
            "schema_version": SCHEMA_VERSION,
            "previous_state": self.previous_state,
            "new_state": self.new_state,
            "reason": self.reason,
            "proof_id": self.proof_id,
            "agent_id": self.agent_id,
        }


@dataclass
class AuthorityStateRecord:
    agent_id: str
    state: AuthorityState = AuthorityState.PROBATION
    trusted_outcomes: int = 0
    failed_outcomes: int = 0
    last_proof_id: str = ""

    def to_dict(self):
        return {
            "schema_version": SCHEMA_VERSION,
            "agent_id": self.agent_id,
            "state": self.state.value,
            "trusted_outcomes": self.trusted_outcomes,
            "failed_outcomes": self.failed_outcomes,
            "last_proof_id": self.last_proof_id,
        }


class AuthorityStateMachine:
    """
    Dynamic authority state for an agent.

    Static capability policy remains the hard ceiling.
    This state only constrains the currently usable authority.
    """

    def __init__(self, agent_id: str):
        if not agent_id:
            raise AuthorityStateError("agent_id_required")

        self.record = AuthorityStateRecord(agent_id=agent_id)
        self.history = []

    @property
    def state(self):
        return self.record.state

    def apply_trust(self, trust_decision):
        if trust_decision is None:
            raise AuthorityStateError("trust_decision_required")

        status = getattr(trust_decision, "status", None)
        proof_id = getattr(trust_decision, "proof_id", "")

        if not proof_id:
            raise AuthorityStateError("proof_id_required")

        previous = self.record.state

        if status == "TRUSTED":
            self.record.trusted_outcomes += 1
            self.record.last_proof_id = proof_id

            if previous == AuthorityState.SUSPENDED:
                new_state = AuthorityState.SUSPENDED
                reason = "suspended_requires_governance_reset"
            elif self.record.trusted_outcomes >= 3:
                new_state = AuthorityState.ELEVATED
                reason = "repeated_trusted_outcomes"
            else:
                new_state = AuthorityState.STANDARD
                reason = "trusted_attested_outcome"

        elif status == "EXPIRED":
            self.record.last_proof_id = proof_id
            new_state = AuthorityState.LIMITED
            reason = "attestation_expired"

        elif status == "UNTRUSTED":
            self.record.failed_outcomes += 1
            self.record.last_proof_id = proof_id
            new_state = AuthorityState.LIMITED
            reason = "untrusted_outcome"

        else:
            raise AuthorityStateError("unknown_trust_status")

        self.record.state = new_state

        transition = AuthorityTransition(
            previous_state=previous.value,
            new_state=new_state.value,
            reason=reason,
            proof_id=proof_id,
            agent_id=self.record.agent_id,
        )

        self.history.append(transition)
        return transition

    def suspend(self, reason: str):
        if not reason:
            raise AuthorityStateError("suspension_reason_required")

        previous = self.record.state
        self.record.state = AuthorityState.SUSPENDED

        transition = AuthorityTransition(
            previous_state=previous.value,
            new_state=AuthorityState.SUSPENDED.value,
            reason=reason,
            agent_id=self.record.agent_id,
        )

        self.history.append(transition)
        return transition

    def governance_reset(self):
        previous = self.record.state
        self.record.state = AuthorityState.PROBATION
        self.record.trusted_outcomes = 0
        self.record.failed_outcomes = 0
        self.record.last_proof_id = ""

        transition = AuthorityTransition(
            previous_state=previous.value,
            new_state=AuthorityState.PROBATION.value,
            reason="governance_reset",
            agent_id=self.record.agent_id,
        )

        self.history.append(transition)
        return transition
