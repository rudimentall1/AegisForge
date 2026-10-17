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



@pytest.mark.parametrize(
    "repository",
    [
        "https://github.com/acme/example?redirect=other",
        "https://github.com/acme/example#fragment",
        "acme/example%2Fother",
        "acme/../example",
    ],
)
def test_repository_identity_rejects_ambiguous_aliases(repository):
    case = case_record()
    report = report_record(source_repository=repository)
    rel, raw = relation(case, report)
    with pytest.raises(CaseEvidenceRelationshipError):
        validate_case_evidence_relationship(case, rel, raw)


def test_exact_target_rejects_noncanonical_uppercase_case_commit():
    case = case_record()
    case["target_commit"] = TARGET_COMMIT.upper()
    report = report_record()
    rel, raw = relation(case, report)
    with pytest.raises(CaseEvidenceRelationshipError, match="target_commit_invalid"):
        validate_case_evidence_relationship(case, rel, raw)

def test_exact_target_rejects_repository_identity_mismatch():
    case = case_record()
    case["target_repository"] = "https://github.com/acme/other"
    report = report_record()
    rel, raw = relation(case, report)
    with pytest.raises(CaseEvidenceRelationshipError, match="target_repository_mismatch"):
        validate_case_evidence_relationship(case, rel, raw)


def test_relationship_rejects_experiment_identity_mismatch():
    case = case_record()
    report = report_record()
    rel, raw = relation(case, report)
    rel["experiment_id"] = "different-experiment"
    with pytest.raises(CaseEvidenceRelationshipError, match="experiment_id_mismatch"):
        validate_case_evidence_relationship(case, rel, raw)


def test_contextual_benchmark_rejects_commit_not_declared_by_report():
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
    rel, raw = relation(case, report, CONTEXTUAL_BENCHMARK, source_commit="f" * 40)
    with pytest.raises(
        CaseEvidenceRelationshipError, match="contextual_commit_not_declared_by_report"
    ):
        validate_case_evidence_relationship(case, rel, raw)


def test_non_finite_json_constants_are_rejected_even_with_matching_digest():
    case = case_record()
    raw = (
        b'{"report_id":"synthetic-source-report-v1",'
        b'"experiment_id":"synthetic-experiment-v1",'
        b'"source_repository":"https://github.com/acme/example",'
        b'"source_commit":"' + TARGET_COMMIT.encode() + b'",'
        b'"unexpected":NaN}'
    )
    rel, _ = relation(case, report_record())
    rel["source_report_sha256"] = hashlib.sha256(raw).hexdigest()
    with pytest.raises(CaseEvidenceRelationshipError, match="source_report_non_finite_number"):
        validate_case_evidence_relationship(case, rel, raw)

@pytest.mark.parametrize("raw", [b"[]", b"null", b'"text"', b""])
def test_non_object_or_empty_source_report_fails_closed(raw):
    case = case_record()
    rel, _ = relation(case, report_record())
    rel["source_report_sha256"] = hashlib.sha256(raw).hexdigest()
    with pytest.raises(CaseEvidenceRelationshipError):
        validate_case_evidence_relationship(case, rel, raw)


@pytest.mark.parametrize("version", [True, 0, 2, "1"])
def test_relationship_schema_version_requires_exact_integer_one(version):
    case = case_record()
    rel, raw = relation(case, report_record())
    rel["schema_version"] = version
    with pytest.raises(
        CaseEvidenceRelationshipError, match="relationship_schema_version_unsupported"
    ):
        validate_case_evidence_relationship(case, rel, raw)


def test_invalid_utf8_source_report_is_rejected():
    case = case_record()
    raw = b'{"report_id":"\xff"}'
    rel, _ = relation(case, report_record())
    rel["source_report_sha256"] = hashlib.sha256(raw).hexdigest()
    with pytest.raises(CaseEvidenceRelationshipError, match="source_report_invalid_json"):
        validate_case_evidence_relationship(case, rel, raw)


def test_deeply_nested_source_report_fails_closed():
    case = case_record()
    raw = b"[" * 3000 + b"0" + b"]" * 3000
    rel, _ = relation(case, report_record())
    rel["source_report_sha256"] = hashlib.sha256(raw).hexdigest()
    with pytest.raises(
        CaseEvidenceRelationshipError, match="source_report_nesting_limit_exceeded"
    ):
        validate_case_evidence_relationship(case, rel, raw)



def test_source_report_over_size_limit_fails_before_json_parsing():
    case = case_record()
    raw = b" " * (2 * 1024 * 1024 + 1)
    rel, _ = relation(case, report_record())
    rel["source_report_sha256"] = hashlib.sha256(raw).hexdigest()
    with pytest.raises(
        CaseEvidenceRelationshipError, match="source_report_size_limit_exceeded"
    ):
        validate_case_evidence_relationship(case, rel, raw)
