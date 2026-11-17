"""Small, fail-closed contract for round technique adapters."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class TechniqueContext:
    technique: str
    role: str
    task: Any
    research_case: Any = None
    round_spec: Any = None


class AgentDelegate(Protocol):
    def run(self, task: Any) -> Any: ...


class Technique(Protocol):
    name: str
    supported_roles: frozenset[str]

    def run(self, context: TechniqueContext, delegate: AgentDelegate | None) -> Any: ...


def not_implemented_result(technique: str, reason: str = "technique_not_implemented") -> dict:
    """Return an explicit terminal result; never pretend an unimplemented method ran."""
    return {
        "status": "NOT_IMPLEMENTED",
        "technique": technique,
        "error": reason,
        "error_type": "TechniqueNotImplemented",
        "execution_performed": False,
    }


class DelegatingTechnique:
    """Route to the existing bounded role agent while preserving technique identity.

    This adapter is intentionally transitional: it provides explicit, testable
    dispatch without replacing the established source/crypto/lab agent logic.
    """

    name = ""
    supported_roles = frozenset({"source_researcher", "crypto_analyst", "lab_runner"})

    def run(self, context: TechniqueContext, delegate: AgentDelegate | None) -> Any:
        if context.role not in self.supported_roles:
            return not_implemented_result(
                self.name, f"role_not_supported:{context.role}"
            )
        if delegate is None:
            return not_implemented_result(self.name, "role_agent_unavailable")
        result = delegate.run(context.task)
        metadata = {
            "technique": self.name,
            "technique_dispatch": {
                "status": "DISPATCHED",
                "adapter": f"agents.techniques.{self.name}",
                "role": context.role,
            },
        }
        # Existing agents commonly return Task objects; annotate their structured
        # result without changing status semantics or discarding existing fields.
        if hasattr(result, "result") and hasattr(result, "status"):
            value = result.result
            if isinstance(value, dict):
                value.update(metadata)
            elif value is None:
                result.result = metadata
            else:
                result.result = {"agent_result": value, **metadata}
            return result
        if isinstance(result, dict):
            return {**result, **metadata}
        return {"agent_result": result, **metadata}
