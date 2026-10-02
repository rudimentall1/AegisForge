from dataclasses import dataclass
import hashlib


SCHEMA_VERSION = "agent-identity-v1"


class AgentIdentityError(ValueError):
    pass


@dataclass(frozen=True)
class AgentIdentity:
    """Immutable runtime identity. Role is authorization metadata, not identity."""

    agent_id: str
    role: str
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self):
        if not self.agent_id:
            raise AgentIdentityError("agent_id_required")
        if not self.role:
            raise AgentIdentityError("agent_role_required")
        if self.schema_version != SCHEMA_VERSION:
            raise AgentIdentityError("unsupported_agent_identity_schema")

    def to_dict(self):
        return {
            "agent_id": self.agent_id,
            "role": self.role,
            "schema_version": self.schema_version,
        }

    @classmethod
    def for_worker(cls, role: str, hostname: str):
        if not role or not hostname:
            raise AgentIdentityError("worker_identity_inputs_required")
        seed = f"aegisforge:{SCHEMA_VERSION}:{hostname}:{role}".encode("utf-8")
        digest = hashlib.sha256(seed).hexdigest()[:32]
        return cls(agent_id=f"af-{digest}", role=role)
