"""Cryptographic primitive review round adapter."""
from shared.techniques.base import DelegatingTechnique


class CryptoPrimitiveAnalysisTechnique(DelegatingTechnique):
    name = "crypto_primitive_analysis"
    supported_roles = frozenset({"crypto_analyst", "source_researcher"})
