import hashlib
import json

import pytest

from shared.onchain_research_case import (
    OnchainResearchCase,
    OnchainResearchCaseError,
    onchain_case_binding,
    verify_onchain_case_binding,
    validate_onchain_task_binding,
)


def valid_case(**overrides):
    values = {
        "case_id": "base-vault-review-001",
        "target_id": "a" * 64,
        "scope_url": "https://immunefi.com/bug-bounty/example/scope/",
        "scope_digest": "b" * 64,
        "scope_reviewed_on": "2026-11-21",
        "authorization_reference": "https://immunefi.com/bug-bounty/example/",
        "hypothesis": "A public entry point may violate the accounting invariant.",
        "expected_invariant": "Total liabilities never exceed assets.",
        "falsification_criteria": "Counterexamples fail under independent source review.",
    }
    values.update(overrides)
    return OnchainResearchCase(**values)


def test_valid_onchain_case_is_immutable_and_binds_target():
    case = valid_case()
    assert case.target_id == "a" * 64
    with pytest.raises((AttributeError, TypeError)):
        case.target_id = "c" * 64


@pytest.mark.parametrize("field,value", [
    ("target_id", "not-a-target"),
    ("scope_digest", "x" * 64),
    ("scope_url", "http://example.com/scope"),
    ("authorization_reference", "javascript:alert(1)"),
    ("scope_reviewed_on", "yesterday"),
])
def test_invalid_scope_or_target_evidence_is_rejected(field, value):
    with pytest.raises(OnchainResearchCaseError):
        valid_case(**{field: value})


def test_onchain_case_rejects_runtime_or_unapproved_techniques():
    with pytest.raises(OnchainResearchCaseError, match="technique_not_allowed"):
        valid_case(allowed_techniques=("runtime_probe",))


def test_binding_round_trip_and_tamper_detection():
    binding = onchain_case_binding(valid_case())
    restored = verify_onchain_case_binding(binding)
    assert restored == valid_case()
    binding["case"]["hypothesis"] = "tampered"
    with pytest.raises(OnchainResearchCaseError, match="digest_mismatch"):
        verify_onchain_case_binding(binding)


def test_binding_rejects_tampered_payload_even_with_recomputed_digest():
    binding = onchain_case_binding(valid_case())
    binding["case"]["target_id"] = "z" * 64
    canonical = json.dumps(binding["case"], sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    binding["case_digest"] = hashlib.sha256(canonical.encode()).hexdigest()
    with pytest.raises(OnchainResearchCaseError, match="payload_invalid"):
        verify_onchain_case_binding(binding)


def test_task_binding_requires_matching_registered_case():
    case = valid_case()
    assert validate_onchain_task_binding(case, case.case_id) is case
    with pytest.raises(OnchainResearchCaseError, match="not_registered"):
        validate_onchain_task_binding(None, case.case_id)
    with pytest.raises(OnchainResearchCaseError, match="mismatch"):
        validate_onchain_task_binding(case, "other-case")
