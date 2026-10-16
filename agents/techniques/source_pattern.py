"""Source-pattern round adapter."""
from shared.techniques.base import DelegatingTechnique


class SourcePatternTechnique(DelegatingTechnique):
    name = "source_pattern"
    supported_roles = frozenset({"source_researcher", "crypto_analyst", "lab_runner"})
