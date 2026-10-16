import pytest
from pydantic import ValidationError

from shared.evidence_ledger import (
    EVIDENCE_SCHEMA_VERSION,
    EvidenceArtifact,
    Finding,
    Hypothesis,
    VerificationCheck,
    deserialize_record,
    deserialize_research_case,
    serialize_record,
    serialize_research_case,
)
from shared.research_case import ResearchCase


def valid_case():
    return ResearchCase(
        case_id="case-001",
        target_repository="example/project",
        target_commit="a" * 40,
        scope_url="https://example.org/scope",
        scope_digest="b" * 64,
        scope_reviewed_on="2026-10-16",
        hypothesis="A bounded invariant can be violated",
        attacker_capability="An unprivileged caller can invoke the public method",
        expected_invariant="Only authorized callers can change the protected value",
        falsification_criteria="The same caller cannot change the value in the pinned local test",
    )


def valid_hypothesis():
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "hypothesis_id": "hyp-1",
        "claim": "Public call bypasses authorization",
        "affected_component": "Vault.withdraw",
        "source_revision": "a" * 40,
        "source_locations": ["src/Vault.sol:42"],
        "attacker_capability": "Unprivileged contract caller",
        "preconditions": ["Vault is initialized"],
        "expected_invariant": "Only owner can withdraw",
        "reproduction_procedure": "Run the isolated Foundry test",
        "counter_test": "Owner withdrawal succeeds",
        "impact_path": "Unauthorized asset withdrawal",
        "scope_reference": "https://example.org/scope",
        "scope_status": "IN_SCOPE",
        "conclusion": "INCONCLUSIVE",
        "evidence_refs": ["artifact-1"],
    }


def valid_artifact():
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "artifact_id": "artifact-1",
        "case_id": "case-001",
        "target_revision": "a" * 40,
        "scope_reference": "https://example.org/scope",
        "hypothesis_id": "hyp-1",
        "relative_path": "logs/test.txt",
        "media_type": "text/plain",
        "sha256": "c" * 64,
        "size_bytes": 12,
    }


def test_existing_research_case_round_trips_without_duplicate_model():
    original = valid_case()
    envelope = serialize_research_case(original)
    assert envelope["schema_version"] == EVIDENCE_SCHEMA_VERSION
    restored = deserialize_research_case(envelope)
    assert isinstance(restored, ResearchCase)
    assert restored == original


@pytest.mark.parametrize("field", ["target_commit", "scope_url", "attacker_capability"])
def test_research_case_required_security_fields_fail_closed(field):
    envelope = serialize_research_case(valid_case())
    del envelope["data"][field]
    with pytest.raises((ValidationError, ValueError, TypeError)):
        deserialize_research_case(envelope)


def test_research_case_envelope_rejects_unknown_version():
    envelope = serialize_research_case(valid_case())
    envelope["schema_version"] = "aegisforge-evidence-v999"
    with pytest.raises(ValueError, match="schema_version"):
        deserialize_research_case(envelope)


def test_hypothesis_round_trip_and_required_fields():
    record = Hypothesis(**valid_hypothesis())
    assert deserialize_record(Hypothesis, serialize_record(record)) == record
    invalid = valid_hypothesis()
    del invalid["attacker_capability"]
    with pytest.raises(ValidationError):
        Hypothesis(**invalid)


def test_artifact_requires_target_revision_scope_and_attacker_capability_is_in_hypothesis():
    artifact = EvidenceArtifact(**valid_artifact())
    assert deserialize_record(EvidenceArtifact, serialize_record(artifact)) == artifact
    invalid = valid_artifact()
    del invalid["target_revision"]
    with pytest.raises(ValidationError):
        EvidenceArtifact(**invalid)
    invalid = valid_artifact()
    invalid["unreviewed_extra"] = True
    with pytest.raises(ValidationError):
        EvidenceArtifact(**invalid)


def test_verification_check_and_finding_round_trip():
    check = VerificationCheck(
        schema_version=EVIDENCE_SCHEMA_VERSION,
        check_id="check-1",
        level=1,
        status="PASS",
        detail="Manifest hashes match",
        artifact_refs=["artifact-1"],
    )
    finding = Finding(
        schema_version=EVIDENCE_SCHEMA_VERSION,
        finding_id="finding-1",
        case_id="case-001",
        hypothesis_id="hyp-1",
        title="Authorization bypass",
        claim="Unprivileged caller can withdraw",
        impact="Unauthorized asset loss",
        severity_rationale="Impact requires reproducible asset loss",
        conclusion="INCONCLUSIVE",
        evidence_refs=["artifact-1"],
    )
    assert deserialize_record(VerificationCheck, serialize_record(check)) == check
    assert deserialize_record(Finding, serialize_record(finding)) == finding
