import hashlib
import json

import pytest

from tools.evm_key_forensics.case_evidence_relationship import (
    CONTEXTUAL_BENCHMARK,
    EXACT_TARGET_REVISION,
    CaseEvidenceRelationshipError,
    immutable_case_contract_sha256,
    validate_case_evidence_relationship,
)


TARGET_COMMIT = "a" * 40
BENCHMARK_COMMIT = "b" * 40


def case_record():
    return {
        "case_id": "case-synthetic-001",
        "target_repository": "https://github.com/acme/example",
        "target_commit": TARGET_COMMIT,
        "scope_url": "https://example.test/scope",
        "scope_digest": "c" * 64,
        "scope_reviewed_on": "2026-10-01",
        "hypothesis": "Synthetic invariant may be violated",
        "attacker_capability": "Unprivileged caller",
        "expected_invariant": "Unauthorized state changes are rejected",
        "falsification_criteria": "All unauthorized calls revert",
        "rounds": [],
        "execution_mode": "local",
        "status": "ready",
    }


def report_record(**updates):
    report = {
        "schema_version": 1,
        "report_id": "synthetic-source-report-v1",
        "experiment_id": "synthetic-experiment-v1",
        "source_repository": "https://github.com/acme/example",
        "source_commit": TARGET_COMMIT,
    }
    report.update(updates)
    return report


def relation(case, report, relationship_type=EXACT_TARGET_REVISION, **updates):
    raw = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    value = {
        "schema_version": 1,
        "case_id": case["case_id"],
        "case_contract_sha256": immutable_case_contract_sha256(case),
        "relationship_type": relationship_type,
        "report_id": report["report_id"],
        "experiment_id": report["experiment_id"],
        "source_repository": report.get("source_repository", report.get("upstream_repository")),
        "source_commit": report.get(
            "source_commit",
            report.get("source_comparison", {}).get("pre_disclosure", {}).get("commit"),
        ),
        "source_report_sha256": hashlib.sha256(raw).hexdigest(),
    }
    value.update(updates)
    return value, raw


def test_exact_target_revision_accepts_exact_repo_commit_and_report_digest():
    case = case_record()
    report = report_record()
    rel, raw = relation(case, report)
    result = validate_case_evidence_relationship(case, rel, raw)
    assert result["relationship_type"] == EXACT_TARGET_REVISION
    assert result["source_report_sha256"] == hashlib.sha256(raw).hexdigest()


def test_lifecycle_status_does_not_change_immutable_case_digest():
    case = case_record()
    before = immutable_case_contract_sha256(case)
    case["status"] = "inconclusive"
    assert immutable_case_contract_sha256(case) == before


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        ({"case_id": "case-synthetic-other"}, "case_id_mismatch"),
        ({"relationship_type": "UNKNOWN"}, "relationship_type_invalid"),
        ({"source_report_sha256": "0" * 64}, "source_report_digest_mismatch"),
        ({"source_commit": "b" * 40}, "target_commit_mismatch"),
        ({"case_contract_sha256": "d" * 64}, "case_contract_digest_mismatch"),
    ],
)
def test_exact_target_rejects_semantic_mismatch(mutation, error):
    case = case_record()
    report = report_record()
    rel, raw = relation(case, report, **mutation)
    with pytest.raises(CaseEvidenceRelationshipError, match=error):
        validate_case_evidence_relationship(case, rel, raw)


def test_contextual_benchmark_accepts_declared_revision_but_not_as_target_evidence():
    case = case_record()
    report = {
        "schema_version": 1,
        "report_id": "historical-comparison-v1",
        "experiment_id": "historical-experiment-v1",
        "upstream_repository": "https://github.com/johguse/profanity",
        "source_comparison": {
            "pre_disclosure": {"commit": BENCHMARK_COMMIT},
            "post_disclosure_archive": {"commit": "e" * 40},
        },
    }
    rel, raw = relation(case, report, CONTEXTUAL_BENCHMARK)
    result = validate_case_evidence_relationship(case, rel, raw)
    assert result["relationship_type"] == CONTEXTUAL_BENCHMARK
    rel["relationship_type"] = EXACT_TARGET_REVISION
    with pytest.raises(
        CaseEvidenceRelationshipError,
        match="exact_target_report_requires_explicit_source_identity",
    ):
        validate_case_evidence_relationship(case, rel, raw)


def test_report_identity_mismatch_is_rejected_even_if_report_digest_is_recomputed():
    case = case_record()
    report = report_record(report_id="changed-report-id")
    rel, raw = relation(case, report)
    rel["report_id"] = "synthetic-source-report-v1"
    with pytest.raises(CaseEvidenceRelationshipError, match="report_id_mismatch"):
        validate_case_evidence_relationship(case, rel, raw)


def test_duplicate_report_json_keys_are_rejected():
    case = case_record()
    raw = (
        b'{"report_id":"one","report_id":"two","experiment_id":"e",'
        b'"source_repository":"https://github.com/acme/example","source_commit":"'
        + TARGET_COMMIT.encode()
        + b'"}'
    )
    rel, _ = relation(case, report_record())
    rel["source_report_sha256"] = hashlib.sha256(raw).hexdigest()
    with pytest.raises(CaseEvidenceRelationshipError, match="source_report_duplicate_json_key"):
        validate_case_evidence_relationship(case, rel, raw)


def test_unknown_relationship_fields_are_rejected():
    case = case_record()
    rel, raw = relation(case, report_record())
    rel["attestation"] = "trusted"
    with pytest.raises(CaseEvidenceRelationshipError, match="relationship_schema_mismatch"):
        validate_case_evidence_relationship(case, rel, raw)
