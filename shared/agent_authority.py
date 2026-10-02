from dataclasses import dataclass
import sqlite3

from shared.authority_state import AuthorityState, AuthorityStateError, AuthorityStateMachine, AuthorityStateStore
from shared.authority_transition import AuthorityTransitionPolicy
from shared.capability_policy import CapabilityPolicy
from shared.effective_capability import evaluate_effective_capability


SCHEMA_VERSION = "agent-authority-registry-v1"


class AgentAuthorityError(ValueError):
    pass


@dataclass(frozen=True)
class AgentAuthority:
    agent_id: str
    policy_version: str
    state: AuthorityState
    trusted_outcomes: int
    failed_outcomes: int
    last_proof_id: str
    authority_epoch: int

    def to_dict(self):
        return {
            "schema_version": SCHEMA_VERSION,
            "agent_id": self.agent_id,
            "policy_version": self.policy_version,
            "state": self.state.value,
            "trusted_outcomes": self.trusted_outcomes,
            "failed_outcomes": self.failed_outcomes,
            "last_proof_id": self.last_proof_id,
            "authority_epoch": self.authority_epoch,
        }


class AgentAuthorityRegistry:
    """Single source of truth for an agent's current authority context."""

    def __init__(self, db, policy=None, transition_policy=None):
        self.db = db
        self.policy = policy or CapabilityPolicy()
        self.transition_policy = transition_policy or AuthorityTransitionPolicy()
        self.state_store = AuthorityStateStore(db)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS agent_authority_registry (
                agent_id TEXT PRIMARY KEY,
                policy_version TEXT NOT NULL,
                authority_epoch INTEGER NOT NULL,
                schema_version TEXT NOT NULL
            )
        """)
        self.db.commit()

    def register(self, agent_id, policy_version=None):
        if not agent_id:
            raise AgentAuthorityError("agent_id_required")
        existing = self.db.execute(
            "SELECT agent_id,policy_version,authority_epoch FROM agent_authority_registry WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()
        if existing:
            return self.get(agent_id)
        version = str(policy_version or self.policy.VERSION)
        machine = AuthorityStateMachine(agent_id, self.transition_policy)
        self.state_store.save(machine)
        self.db.execute(
            "INSERT INTO agent_authority_registry(agent_id,policy_version,authority_epoch,schema_version) VALUES(?,?,?,?)",
            (agent_id, version, 1, SCHEMA_VERSION),
        )
        self.db.commit()
        return self.get(agent_id)

    def get(self, agent_id):
        if not agent_id:
            raise AgentAuthorityError("agent_id_required")
        row = self.db.execute(
            "SELECT agent_id,policy_version,authority_epoch FROM agent_authority_registry WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()
        if row is None:
            raise AgentAuthorityError("agent_not_registered")
        machine = self.state_store.load(agent_id)
        machine.transition_policy = self.transition_policy
        return AgentAuthority(
            agent_id=row[0],
            policy_version=row[1],
            state=machine.state,
            trusted_outcomes=machine.record.trusted_outcomes,
            failed_outcomes=machine.record.failed_outcomes,
            last_proof_id=machine.record.last_proof_id,
            authority_epoch=int(row[2]),
        )

    def _machine(self, agent_id):
        self.get(agent_id)
        machine = self.state_store.load(agent_id)
        machine.transition_policy = self.transition_policy
        return machine

    def _save_machine(self, machine):
        self.state_store.save(machine)

    def record_trust(self, agent_id, trust_decision):
        machine = self._machine(agent_id)
        transition = machine.apply_trust(trust_decision)
        self._save_machine(machine)
        return self.get(agent_id), transition

    def evaluate(self, agent_id, intent):
        authority = self.get(agent_id)
        return evaluate_effective_capability(intent, authority.state, self.policy)

    def governance_promote_elevated(self, agent_id, reason, proof_id=""):
        machine = self._machine(agent_id)
        transition = machine.governance_promote_elevated(reason, proof_id)
        self._save_machine(machine)
        return self.get(agent_id), transition

    def suspend(self, agent_id, reason):
        machine = self._machine(agent_id)
        transition = machine.suspend(reason)
        self._save_machine(machine)
        return self.get(agent_id), transition

    def governance_reset(self, agent_id, reason="governance_reset"):
        if not reason:
            raise AgentAuthorityError("reset_reason_required")
        machine = self._machine(agent_id)
        transition = machine.governance_reset()
        self._save_machine(machine)
        self._increment_epoch(agent_id)
        return self.get(agent_id), transition

    def rotate_policy(self, agent_id, policy_version):
        if not policy_version:
            raise AgentAuthorityError("policy_version_required")
        self.get(agent_id)
        self.db.execute(
            "UPDATE agent_authority_registry SET policy_version=?,authority_epoch=authority_epoch+1 WHERE agent_id=?",
            (str(policy_version), agent_id),
        )
        self.db.commit()
        return self.get(agent_id)

    def _increment_epoch(self, agent_id):
        self.db.execute(
            "UPDATE agent_authority_registry SET authority_epoch=authority_epoch+1 WHERE agent_id=?",
            (agent_id,),
        )
        self.db.commit()

