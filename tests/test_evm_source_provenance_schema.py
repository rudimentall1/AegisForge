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



def test_signed_provenance_attestation_requires_operator_trusted_key(monkeypatch):
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from agents.validator.agent import Validator
    import json

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    monkeypatch.setenv(
        "AEGISFORGE_PROVENANCE_TRUSTED_PUBLIC_KEYS",
        json.dumps({"reviewer-test-key": base64.b64encode(public_key).decode("ascii")}),
    )
    trusted_keys, config_error = Validator._load_provenance_trust_keys()
    assert config_error is None
    assert set(trusted_keys) == {"reviewer-test-key"}

    payload = {
        "attestation_version": "evm-provenance-attestation-v1",
        "source_id": "source-a",
        "publisher_verification_status": "VERIFIED",
        "origin_status": "PRIMARY_ORIGIN_VERIFIED",
        "canonical_origin_ref": "https://example.org/advisory",
        "independence_status": "ESTABLISHED",
        "independence_basis": "VERIFIED_DISTINCT_ORIGINS",
        "evidence_ref": "review-record:case-17",
        "reviewed_by": "security-reviewer-17",
        "reviewed_at": "2026-10-13T12:00:00Z",
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    attestation = {
        "key_id": "reviewer-test-key",
        "payload": payload,
        "signature": base64.b64encode(private_key.sign(canonical)).decode("ascii"),
    }

    verified = Validator._verify_provenance_attestation(attestation, "source-a", trusted_keys)
    assert verified["status"] == "SIGNATURE_VERIFIED"
    assert verified["trusted_signer"] is True
    assert verified["independence_status"] == "ESTABLISHED"
    assert "not independently re-evaluated" in verified["interpretation"]

    tampered_payload = dict(payload, independence_status="UNKNOWN")
    tampered = dict(attestation, payload=tampered_payload)
    rejected = Validator._verify_provenance_attestation(tampered, "source-a", trusted_keys)
    assert rejected["status"] == "INVALID_SIGNATURE"
    assert rejected["trusted_signer"] is False

    unknown_key = dict(attestation, key_id="not-in-trust-store")
    rejected_unknown = Validator._verify_provenance_attestation(unknown_key, "source-a", trusted_keys)
    assert rejected_unknown["status"] == "UNTRUSTED_SIGNER"
    assert rejected_unknown["trusted_signer"] is False


def test_signed_provenance_attestation_rejects_source_id_mismatch(monkeypatch):
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from agents.validator.agent import Validator
    import json

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    monkeypatch.setenv(
        "AEGISFORGE_PROVENANCE_TRUSTED_PUBLIC_KEYS",
        json.dumps({"reviewer-test-key": base64.b64encode(public_key).decode("ascii")}),
    )
    trusted_keys, _ = Validator._load_provenance_trust_keys()
    payload = {
        "attestation_version": "evm-provenance-attestation-v1",
        "source_id": "source-a",
        "publisher_verification_status": "UNKNOWN",
        "origin_status": "UNKNOWN",
        "canonical_origin_ref": "",
        "independence_status": "NOT_ESTABLISHED",
        "independence_basis": "NO_VERIFIED_PROVENANCE",
        "evidence_ref": "review-record:case-18",
        "reviewed_by": "security-reviewer-18",
        "reviewed_at": "2026-10-13T12:00:00Z",
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    attestation = {
        "key_id": "reviewer-test-key",
        "payload": payload,
        "signature": base64.b64encode(private_key.sign(canonical)).decode("ascii"),
    }
    result = Validator._verify_provenance_attestation(attestation, "source-b", trusted_keys)
    assert result["status"] == "INVALID_PAYLOAD"
    assert result["trusted_signer"] is False



def test_validator_report_records_signed_attestation_without_promoting_claims(monkeypatch):
    """Integration contract: valid signatures are reported, not treated as proof of independence."""
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from agents.validator.agent import Validator
    from shared.task import Task

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    monkeypatch.setenv(
        "AEGISFORGE_PROVENANCE_TRUSTED_PUBLIC_KEYS",
        json.dumps({"reviewer-integration-key": base64.b64encode(public_key).decode("ascii")}),
    )
    payload = {
        "attestation_version": "evm-provenance-attestation-v1",
        "source_id": "source-integration-a",
        "publisher_verification_status": "VERIFIED",
        "origin_status": "PRIMARY_ORIGIN_VERIFIED",
        "canonical_origin_ref": "https://example.org/advisory",
        "independence_status": "ESTABLISHED",
        "independence_basis": "VERIFIED_DISTINCT_ORIGINS",
        "evidence_ref": "review-record:integration-case",
        "reviewed_by": "integration-reviewer",
        "reviewed_at": "2026-10-13T12:00:00Z",
    }
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    attestation = {
        "key_id": "reviewer-integration-key",
        "payload": payload,
        "signature": base64.b64encode(private_key.sign(canonical)).decode("ascii"),
    }
    task = Task(
        task_id="signed-provenance-integration",
        description="A trusted signature must not be confused with independent evidence",
        result={
            "research_track": "evm_key_forensics",
            "stage": "source_research",
            "sources": [{
                "source_id": "source-integration-a",
                "source_url": "",
                "provenance_attestation": attestation,
            }],
            "source_leads": [],
            "hypotheses": [],
            "lab_experiments": [],
        },
    )

    validated = Validator(source_fetcher=lambda _url: {}).run(task)
    report = validated.result["research_validation"]
    claim = report["source_provenance_claims"][0]

    assert report["source_provenance_claims_received"] == 1
    assert claim["attestation_status"] == "SIGNATURE_VERIFIED"
    assert claim["attestation_key_id"] == "reviewer-integration-key"
    assert report["signed_provenance_attestations_checked"] == 1
    assert report["signed_provenance_attestations_verified"] == 1
    assert report["signed_provenance_attestation_checks"][0]["source_id"] == "source-integration-a"
    assert report["source_provenance_claims_independently_verified"] is False
    assert report["source_origin_independence_established"] is False
    assert "submitted_source_provenance_requires_independent_verification" in report["readiness_blockers"]
    assert report["status"] == "INCONCLUSIVE"



def test_conflicting_signed_provenance_attestations_require_review(monkeypatch):
    """Opposing trusted signatures for one source must remain explicitly conflicted."""
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from agents.validator.agent import Validator
    from shared.task import Task

    reviewers = {
        "reviewer-a": Ed25519PrivateKey.generate(),
        "reviewer-b": Ed25519PrivateKey.generate(),
    }
    trusted_public_keys = {
        key_id: base64.b64encode(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).decode("ascii")
        for key_id, private_key in reviewers.items()
    }
    monkeypatch.setenv(
        "AEGISFORGE_PROVENANCE_TRUSTED_PUBLIC_KEYS",
        json.dumps(trusted_public_keys),
    )

    common = {
        "attestation_version": "evm-provenance-attestation-v1",
        "source_id": "same-source",
        "publisher_verification_status": "VERIFIED",
        "origin_status": "PRIMARY_ORIGIN_VERIFIED",
        "canonical_origin_ref": "https://example.org/advisory",
        "evidence_ref": "review-record:conflict-case",
        "reviewed_at": "2026-10-13T12:00:00Z",
    }
    payloads = [
        {
            **common,
            "independence_status": "ESTABLISHED",
            "independence_basis": "VERIFIED_DISTINCT_ORIGINS",
            "reviewed_by": "reviewer-a",
        },
        {
            **common,
            "independence_status": "DEPENDENT",
            "independence_basis": "SHARED_ORIGIN",
            "reviewed_by": "reviewer-b",
        },
    ]
    sources = []
    for (key_id, private_key), payload in zip(reviewers.items(), payloads):
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        sources.append({
            "source_id": "same-source",
            "source_url": "",
            "provenance_attestation": {
                "key_id": key_id,
                "payload": payload,
                "signature": base64.b64encode(private_key.sign(canonical)).decode("ascii"),
            },
        })

    task = Task(
        task_id="conflicting-signed-provenance",
        description="Conflicting signed provenance claims must not be silently resolved",
        result={
            "research_track": "evm_key_forensics",
            "stage": "source_research",
            "sources": sources,
            "source_leads": [],
            "hypotheses": [],
            "lab_experiments": [],
        },
    )
    validated = Validator(source_fetcher=lambda _url: {}).run(task)
    report = validated.result["research_validation"]

    assert report["signed_provenance_attestations_verified"] == 2
    conflicts = report["conflicting_signed_provenance_attestations"]
    assert len(conflicts) == 1
    assert conflicts[0]["source_id"] == "same-source"
    assert conflicts[0]["signer_key_ids"] == ["reviewer-a", "reviewer-b"]
    assert conflicts[0]["conflicting_fields"]["independence_status"] == ["DEPENDENT", "ESTABLISHED"]
    assert conflicts[0]["resolution"] == "HUMAN_REVIEW_REQUIRED"
    assert "conflicting_signed_provenance_attestations_require_review" in report["readiness_blockers"]
    assert report["source_origin_independence_established"] is False
    assert report["status"] == "INCONCLUSIVE"


def test_provenance_trust_store_fails_closed_on_duplicate_keys_and_bad_base64(monkeypatch):
    from agents.validator.agent import Validator

    malformed_configs = [
        '{"reviewer-key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","reviewer-key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}',
        '{"reviewer-key":"not-valid-base64***"}',
        '{"reviewer-key":"AAAAAAAA"}',
        '[]',
    ]
    for raw_config in malformed_configs:
        monkeypatch.setenv("AEGISFORGE_PROVENANCE_TRUSTED_PUBLIC_KEYS", raw_config)
        trusted_keys, config_error = Validator._load_provenance_trust_keys()
        assert trusted_keys == {}
        assert config_error is not None


def test_provenance_trust_store_fails_closed_on_duplicate_json_keys(monkeypatch):
    from agents.validator.agent import Validator

    monkeypatch.setenv(
        "AEGISFORGE_PROVENANCE_TRUSTED_PUBLIC_KEYS",
        '{"reviewer-key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","reviewer-key":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="}',
    )
    trusted_keys, config_error = Validator._load_provenance_trust_keys()
    assert trusted_keys == {}
    assert config_error == "ValueError"
