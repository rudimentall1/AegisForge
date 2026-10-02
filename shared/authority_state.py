from dataclasses import dataclass
from enum import Enum
import sqlite3


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


class AuthorityStateStore:
    """SQLite persistence for dynamic authority state and transitions."""

    def __init__(self, db):
        self.db = db
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS authority_state (
                agent_id TEXT PRIMARY KEY,
                state TEXT NOT NULL,
                trusted_outcomes INTEGER NOT NULL DEFAULT 0,
                failed_outcomes INTEGER NOT NULL DEFAULT 0,
                last_proof_id TEXT NOT NULL DEFAULT '',
                schema_version TEXT NOT NULL
            )
        """)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS authority_transitions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                previous_state TEXT NOT NULL,
                new_state TEXT NOT NULL,
                reason TEXT NOT NULL,
                proof_id TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                schema_version TEXT NOT NULL
            )
        """)
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_authority_transitions_agent ON authority_transitions(agent_id, id)")
        self.db.commit()

    def load(self, agent_id):
        if not agent_id:
            raise AuthorityStateError("agent_id_required")
        row = self.db.execute(
            "SELECT agent_id,state,trusted_outcomes,failed_outcomes,last_proof_id FROM authority_state WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()
        if row is None:
            return AuthorityStateMachine(agent_id)
        try:
            state = AuthorityState(row[1])
        except ValueError as exc:
            raise AuthorityStateError("invalid_persisted_state") from exc
        machine = AuthorityStateMachine(agent_id)
        machine.record = AuthorityStateRecord(
            agent_id=row[0], state=state, trusted_outcomes=int(row[2]),
            failed_outcomes=int(row[3]), last_proof_id=row[4] or "",
        )
        rows = self.db.execute(
            "SELECT previous_state,new_state,reason,proof_id FROM authority_transitions WHERE agent_id = ? ORDER BY id",
            (agent_id,),
        ).fetchall()
        machine.history = [AuthorityTransition(*row, agent_id=agent_id) for row in rows]
        return machine

    def save(self, machine):
        if not isinstance(machine, AuthorityStateMachine):
            raise AuthorityStateError("authority_machine_required")
        r = machine.record
        self.db.execute(
            """INSERT INTO authority_state(agent_id,state,trusted_outcomes,failed_outcomes,last_proof_id,schema_version)
               VALUES(?,?,?,?,?,?)
               ON CONFLICT(agent_id) DO UPDATE SET state=excluded.state,
               trusted_outcomes=excluded.trusted_outcomes, failed_outcomes=excluded.failed_outcomes,
               last_proof_id=excluded.last_proof_id, schema_version=excluded.schema_version""",
            (r.agent_id, r.state.value, r.trusted_outcomes, r.failed_outcomes, r.last_proof_id, SCHEMA_VERSION),
        )
        self.db.execute("DELETE FROM authority_transitions WHERE agent_id = ?", (r.agent_id,))
        from datetime import datetime, timezone
        for transition in machine.history:
            self.db.execute(
                """INSERT INTO authority_transitions(agent_id,previous_state,new_state,reason,proof_id,created_at,schema_version)
                   VALUES(?,?,?,?,?,?,?)""",
                (transition.agent_id, transition.previous_state, transition.new_state,
                 transition.reason, transition.proof_id, datetime.now(timezone.utc).isoformat(), SCHEMA_VERSION),
            )
        self.db.commit()
