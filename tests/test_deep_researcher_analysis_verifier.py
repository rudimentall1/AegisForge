import hashlib
import json

from agents.deep_researcher.analysis_verifier import verify_analysis_evidence


SOURCE = b"pragma solidity ^0.8.20; contract Vault {}"
ANALYSIS = {
    "schema": "aegisforge.slither_analysis.v1",
    "status": "ANALYZED",
    "findings": [
        {
            "detector": "reentrancy-eth",
            "impact": "HIGH",
            "confidence": "MEDIUM",
            "description": "Potential reentrancy.",
            "elements": [],
            "status": "UNVERIFIED_POTENTIAL",
        }
    ],
    "finding_count": 1,
    "vulnerabilities_confirmed": False,
}


def encoded_analysis(payload=ANALYSIS):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def verify(source=SOURCE, payload=ANALYSIS):
    analysis_bytes = encoded_analysis(payload)
    return verify_analysis_evidence(
        source_bytes=source,
        analysis_bytes=analysis_bytes,
        expected_source_sha256=hashlib.sha256(SOURCE).hexdigest(),
        expected_analysis_sha256=hashlib.sha256(analysis_bytes).hexdigest(),
    )


def test_verifier_accepts_matching_persisted_evidence_without_confirming_vulnerability():
    result = verify()

    assert result["status"] == "VALID"
    assert result["validation_scope"] == "artifact_integrity_only"
    assert all(result["checks"].values())
    assert result["vulnerabilities_confirmed"] is False


def test_verifier_rejects_source_hash_mismatch():
    result = verify(source=b"tampered source")

    assert result["status"] == "INVALID"
    assert result["checks"]["source_sha256_matches"] is False
    assert result["vulnerabilities_confirmed"] is False


def test_verifier_rejects_analysis_hash_mismatch():
    analysis_bytes = encoded_analysis()
    result = verify_analysis_evidence(
        source_bytes=SOURCE,
        analysis_bytes=analysis_bytes + b" ",
        expected_source_sha256=hashlib.sha256(SOURCE).hexdigest(),
        expected_analysis_sha256=hashlib.sha256(analysis_bytes).hexdigest(),
    )

    assert result["status"] == "INVALID"
    assert result["checks"]["analysis_sha256_matches"] is False


def test_verifier_rejects_findings_marked_confirmed():
    payload = dict(ANALYSIS)
    payload["findings"] = [dict(ANALYSIS["findings"][0], status="CONFIRMED")]
    result = verify(payload=payload)

    assert result["status"] == "INVALID"
    assert result["checks"]["findings_unconfirmed"] is False
    assert result["vulnerabilities_confirmed"] is False


def test_verifier_rejects_finding_count_mismatch():
    payload = dict(ANALYSIS, finding_count=2)
    result = verify(payload=payload)

    assert result["status"] == "INVALID"
    assert result["checks"]["finding_count_matches"] is False



def test_verifier_rejects_unhashable_status_and_finding_fields():
    invalid_status = dict(ANALYSIS, status=[])
    status_result = verify(payload=invalid_status)
    assert status_result["status"] == "INVALID"

    invalid_finding = dict(ANALYSIS)
    invalid_finding["findings"] = [
        dict(ANALYSIS["findings"][0], impact=[], confidence={})
    ]
    finding_result = verify(payload=invalid_finding)
    assert finding_result["status"] == "INVALID"
