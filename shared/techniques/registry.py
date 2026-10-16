"""Allowlisted registry for deterministic round-technique dispatch."""
from __future__ import annotations

from shared.techniques.base import TechniqueContext, not_implemented_result
from agents.techniques.source_pattern import SourcePatternTechnique
from agents.techniques.differential_revision import DifferentialRevisionTechnique
from agents.techniques.crypto_primitive_analysis import CryptoPrimitiveAnalysisTechnique
from agents.techniques.runtime_probe import RuntimeProbeTechnique
from agents.techniques.fuzzing import FuzzingTechnique
from agents.techniques.symbolic_execution import SymbolicExecutionTechnique
from agents.techniques.formal_verification import FormalVerificationTechnique
from agents.techniques.supply_chain import SupplyChainTechnique


class TechniqueRegistry:
    """Resolve only explicitly registered technique names; unknowns fail closed."""

    def __init__(self):
        instances = (
            SourcePatternTechnique(),
            DifferentialRevisionTechnique(),
            CryptoPrimitiveAnalysisTechnique(),
            RuntimeProbeTechnique(),
            FuzzingTechnique(),
            SymbolicExecutionTechnique(),
            FormalVerificationTechnique(),
            SupplyChainTechnique(),
        )
        self._techniques = {item.name: item for item in instances}

    @property
    def names(self) -> frozenset[str]:
        return frozenset(self._techniques)

    def dispatch(self, technique: str, role: str, task, delegate=None):
        implementation = self._techniques.get(technique)
        if implementation is None:
            return not_implemented_result(
                str(technique or "unknown"), "unknown_technique"
            )
        if role not in implementation.supported_roles:
            return not_implemented_result(
                implementation.name, f"role_not_supported:{role}"
            )
        context = TechniqueContext(
            technique=implementation.name,
            role=role,
            task=task,
            research_case=(getattr(task, "payload", {}) or {}).get("research_case"),
            round_spec=(getattr(task, "payload", {}) or {}).get("round_spec"),
        )
        return implementation.run(context, delegate)
