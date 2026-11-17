"""Pinned-revision comparison round adapter."""
from shared.techniques.base import DelegatingTechnique


class DifferentialRevisionTechnique(DelegatingTechnique):
    name = "differential_revision"
    supported_roles = frozenset({"source_researcher", "crypto_analyst"})
