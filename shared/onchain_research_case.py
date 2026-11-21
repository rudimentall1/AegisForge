"""Immutable authorization and provenance envelope for on-chain research.

This is deliberately separate from the Git-centric ResearchCase. It can authorize
source review and explicitly scoped local exploit reproduction; it never grants
public-network transactions or arbitrary target execution.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import date
import hashlib
import json
import re
from urllib.parse import urlparse


class OnchainResearchCaseError(ValueError):
    """Invalid on-chain research case or task binding."""


@dataclass(frozen=True, slots=True)
class OnchainResearchCase:
    case_id: str
    target_id: str
    scope_url: str
    scope_digest: str
    scope_reviewed_on: str
    authorization_reference: str
    hypothesis: str
    expected_invariant: str
    falsification_criteria: str
    allowed_techniques: tuple[str, ...] = ("source_pattern",)

    def __post_init__(self):
        required = (
            "case_id", "target_id", "scope_url", "scope_digest",
            "scope_reviewed_on", "authorization_reference", "hypothesis",
            "expected_invariant", "falsification_criteria",
        )
        for name in required:
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise OnchainResearchCaseError(f"{name}_required")
        if not re.fullmatch(r"[0-9a-f]{64}", self.target_id):
            raise OnchainResearchCaseError("target_id_invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", self.scope_digest):
            raise OnchainResearchCaseError("scope_digest_invalid")
        for name in ("scope_url", "authorization_reference"):
            parsed = urlparse(getattr(self, name))
            if parsed.scheme != "https" or not parsed.netloc:
                raise OnchainResearchCaseError(f"{name}_must_be_https")
        try:
            date.fromisoformat(self.scope_reviewed_on)
        except (TypeError, ValueError) as exc:
            raise OnchainResearchCaseError("scope_reviewed_on_invalid") from exc
        techniques = self.allowed_techniques
        if isinstance(techniques, list):
            techniques = tuple(techniques)
            object.__setattr__(self, "allowed_techniques", techniques)
        if not isinstance(techniques, tuple) or not techniques:
            raise OnchainResearchCaseError("allowed_techniques_required")
        if any(
            item not in {
                "source_pattern",
                "crypto_primitive_analysis",
                "exploit_reproduction",
            }
            for item in techniques
        ):
            raise OnchainResearchCaseError("onchain_technique_not_allowed")
        if len(set(techniques)) != len(techniques):
            raise OnchainResearchCaseError("duplicate_onchain_technique")


def onchain_case_binding(case: OnchainResearchCase) -> dict:
    if not isinstance(case, OnchainResearchCase):
        raise OnchainResearchCaseError("onchain_case_required")
    payload = asdict(case)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return {
        "schema_version": "aegisforge-onchain-case-v1",
        "case_id": case.case_id,
        "case_digest": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "case": payload,
    }


def verify_onchain_case_binding(binding: dict) -> OnchainResearchCase:
    if not isinstance(binding, dict) or binding.get("schema_version") != "aegisforge-onchain-case-v1":
        raise OnchainResearchCaseError("onchain_case_binding_schema_invalid")
    payload = binding.get("case")
    if not isinstance(payload, dict) or payload.get("case_id") != binding.get("case_id"):
        raise OnchainResearchCaseError("onchain_case_binding_id_mismatch")
    try:
        case = OnchainResearchCase(**payload)
    except (TypeError, ValueError) as exc:
        raise OnchainResearchCaseError("onchain_case_binding_payload_invalid") from exc
    expected = onchain_case_binding(case)
    if expected["case_digest"] != binding.get("case_digest"):
        raise OnchainResearchCaseError("onchain_case_binding_digest_mismatch")
    return case


def validate_onchain_task_binding(case: OnchainResearchCase | None, task_case_id: str | None):
    if case is None:
        raise OnchainResearchCaseError("onchain_case_not_registered")
    if not task_case_id or task_case_id != case.case_id:
        raise OnchainResearchCaseError("onchain_task_case_mismatch")
    return case
