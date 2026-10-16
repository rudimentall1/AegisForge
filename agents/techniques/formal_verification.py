"""Explicit placeholder for formal verification."""
from shared.techniques.base import TechniqueContext, not_implemented_result


class FormalVerificationTechnique:
    name = "formal_verification"
    supported_roles = frozenset({"source_researcher", "crypto_analyst", "lab_runner"})

    def run(self, context: TechniqueContext, delegate=None):
        return not_implemented_result(self.name)
