"""Contract checks for the fail-closed source provenance schema."""

import json
from pathlib import Path


SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "tools"
    / "evm_key_forensics"
    / "source-provenance.schema.json"
)


def test_source_provenance_schema_keeps_integrity_and_independence_separate():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    assert schema["properties"]["schema_version"]["const"] == "evm-source-provenance-v1"
    required = set(schema["required"])
    assert {
        "content_integrity",
        "publisher_identity",
        "origin_relationship",
        "independence_assessment",
    } <= required

    independence = schema["properties"]["independence_assessment"]["properties"]
    assert "NOT_ESTABLISHED" in independence["status"]["enum"]
    assert "UNKNOWN" in independence["status"]["enum"]
    assert "CONTENT_HASH_ONLY" in independence["basis"]["enum"]
    assert "URL_ONLY" in independence["basis"]["enum"]
    assert "NO_VERIFIED_PROVENANCE" in independence["basis"]["enum"]


def test_source_provenance_schema_warns_that_shape_is_not_authenticity():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    description = schema["description"].lower()

    assert "shape only" in description
    assert "does not authenticate publishers" in description
    assert "does not" in description and "independent evidence" in description

    publisher = schema["properties"]["publisher_identity"]["properties"]
    assert "UNVERIFIED" in publisher["verification_status"]["enum"]
    assert "UNKNOWN" in publisher["verification_status"]["enum"]


def test_synthetic_unknown_provenance_example_does_not_infer_independence():
    example_path = (
        Path(__file__).resolve().parents[1]
        / "tools"
        / "evm_key_forensics"
        / "examples"
        / "source-provenance-unknown.json"
    )
    example = json.loads(example_path.read_text(encoding="utf-8"))

    assert example["content_integrity"]["status"] == "MATCHED"
    assert example["publisher_identity"]["verification_status"] == "UNKNOWN"
    assert example["origin_relationship"]["status"] == "UNKNOWN"
    assert example["independence_assessment"]["status"] == "NOT_ESTABLISHED"
    assert example["independence_assessment"]["basis"] == "NO_VERIFIED_PROVENANCE"
    assert any("does not authenticate" in item for item in example["limitations"])


def test_verified_claims_require_reviewer_and_evidence_metadata():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    conditions = schema["allOf"]
    assert len(conditions) == 3

    publisher_rule = next(
        item for item in conditions
        if item.get("if", {}).get("properties", {})
        .get("publisher_identity", {}).get("properties", {})
        .get("verification_status", {}).get("const") == "VERIFIED"
    )
    publisher_then = publisher_rule["then"]["properties"]["publisher_identity"]
    assert {
        "verification_method",
        "verification_evidence_ref",
        "verified_by",
        "verified_at",
    } <= set(publisher_then["required"])
    assert "NONE" not in publisher_then["properties"]["verification_method"]["enum"]

    origin_rule = next(
        item for item in conditions
        if item.get("if", {}).get("properties", {})
        .get("origin_relationship", {}).get("properties", {})
        .get("status", {}).get("const") == "PRIMARY_ORIGIN_VERIFIED"
    )
    assert {
        "canonical_origin_ref",
        "verification_evidence_ref",
    } <= set(origin_rule["then"]["properties"]["origin_relationship"]["required"])

    independence_rule = next(
        item for item in conditions
        if item.get("if", {}).get("properties", {})
        .get("independence_assessment", {}).get("properties", {})
        .get("status", {}).get("const") == "ESTABLISHED"
    )
    independence_then = independence_rule["then"]["properties"]["independence_assessment"]
    assert independence_then["properties"]["basis"]["const"] == "VERIFIED_DISTINCT_ORIGINS"
    assert {
        "review_record_ref",
        "reviewed_by",
        "reviewed_at",
    } <= set(independence_then["required"])



def test_validator_does_not_trust_source_supplied_verified_provenance_claims():
    from agents.validator.agent import Validator
    from shared.task import Task

    task = Task(
        task_id="untrusted-provenance-claim",
        description="Source-supplied provenance statuses must not become verifier results",
        result={
            "research_track": "evm_key_forensics",
            "stage": "source_research",
            "sources": [
                {
                    "source_id": "self-asserted-source",
                    "source_url": "",
                    "provenance_record": {
                        "schema_version": "evm-source-provenance-v1",
                        "content_integrity": {"status": "MATCHED"},
                        "publisher_identity": {
                            "claimed_name": "Example Publisher",
                            "verification_status": "VERIFIED",
                            "verification_method": "PUBLISHER_SIGNING_KEY",
                            "verification_evidence_ref": "https://example.invalid/evidence",
                            "verified_by": "self-asserted-reviewer",
                            "verified_at": "2026-10-13T00:00:00Z",
                        },
                        "origin_relationship": {
                            "status": "PRIMARY_ORIGIN_VERIFIED",
                            "canonical_origin_ref": "https://example.invalid/source",
                            "derived_from_source_ids": [],
                            "verification_evidence_ref": "https://example.invalid/origin-proof",
                        },
                        "independence_assessment": {
                            "status": "ESTABLISHED",
                            "basis": "VERIFIED_DISTINCT_ORIGINS",
                            "review_record_ref": "https://example.invalid/review",
                            "reviewed_by": "self-asserted-reviewer",
                            "reviewed_at": "2026-10-13T00:00:00Z",
                        },
                    },
                }
            ],
            "source_leads": [],
            "hypotheses": [],
            "lab_experiments": [],
        },
    )

    validated = Validator(source_fetcher=lambda _url: {}).run(task)
    report = validated.result["research_validation"]
    claim = report["source_provenance_claims"][0]

    assert report["source_provenance_claims_received"] == 1
    assert claim["claimed_publisher_verification_status"] == "VERIFIED"
    assert claim["claimed_origin_status"] == "PRIMARY_ORIGIN_VERIFIED"
    assert claim["claimed_independence_status"] == "ESTABLISHED"
    assert claim["trust_status"] == "UNVERIFIED_SOURCE_SUPPLIED_CLAIM"
    assert report["source_provenance_claims_independently_verified"] is False
    assert report["source_origin_independence_established"] is False
    assert "submitted_source_provenance_requires_independent_verification" in report["readiness_blockers"]
    assert report["status"] == "INCONCLUSIVE"
