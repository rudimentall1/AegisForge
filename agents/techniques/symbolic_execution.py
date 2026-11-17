"""Explicit placeholder for symbolic execution."""
from shared.techniques.base import TechniqueContext, not_implemented_result


class SymbolicExecutionTechnique:
    name = "symbolic_execution"
    supported_roles = frozenset({"source_researcher", "crypto_analyst", "lab_runner"})

    def run(self, context: TechniqueContext, delegate=None):
        return not_implemented_result(self.name)
