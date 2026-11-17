"""Explicit placeholder for a future sandboxed fuzzing adapter."""
from shared.techniques.base import TechniqueContext, not_implemented_result


class FuzzingTechnique:
    name = "fuzzing"
    supported_roles = frozenset({"source_researcher", "crypto_analyst", "lab_runner"})

    def run(self, context: TechniqueContext, delegate=None):
        return not_implemented_result(self.name)
