"""Bounded local/synthetic runtime probe round adapter."""
from shared.techniques.base import DelegatingTechnique


class RuntimeProbeTechnique(DelegatingTechnique):
    name = "runtime_probe"
    supported_roles = frozenset({"lab_runner"})
