"""Semantic binding between a registered Research Case and source-report bytes.

This validates identity consistency only. It does not authenticate the report author,
source-to-binary provenance, runtime behavior, exploitability, or wallet exposure.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping
from urllib.parse import urlparse

SCHEMA_VERSION = 1
MAX_SOURCE_REPORT_BYTES = 2 * 1024 * 1024
EXACT_TARGET_REVISION = "EXACT_TARGET_REVISION"
CONTEXTUAL_BENCHMARK = "CONTEXTUAL_BENCHMARK"
RELATIONSHIP_TYPES = frozenset({EXACT_TARGET_REVISION, CONTEXTUAL_BENCHMARK})
RELATIONSHIP_FIELDS = frozenset({
    "schema_version",
    "case_id",
    "case_contract_sha256",
    "relationship_type",
    "report_id",
    "experiment_id",
    "source_repository",
    "source_commit",
    "source_report_sha256",
})
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IMMUTABLE_CASE_FIELDS = (
    "case_id", "target_repository", "target_commit", "scope_url", "scope_digest",
    "scope_reviewed_on", "hypothesis", "attacker_capability", "expected_invariant",
    "falsification_criteria", "rounds", "execution_mode",
)


class CaseEvidenceRelationshipError(ValueError):
    """Raised when a case/report relationship is missing or semantically inconsistent."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CaseEvidenceRelationshipError("source_report_duplicate_json_key")
        result[key] = value
    return result


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CaseEvidenceRelationshipError("case_contract_not_canonicalizable") from exc


def immutable_case_contract_sha256(case: Mapping[str, Any]) -> str:
    """Hash only the immutable investigation contract, excluding lifecycle state."""
    if not isinstance(case, Mapping):
        raise CaseEvidenceRelationshipError("case_contract_must_be_object")
    missing = [name for name in IMMUTABLE_CASE_FIELDS if name not in case]
    if missing:
        raise CaseEvidenceRelationshipError("case_contract_missing_fields:" + ",".join(missing))
    contract = {name: case[name] for name in IMMUTABLE_CASE_FIELDS}
    return hashlib.sha256(_canonical_json(contract)).hexdigest()


def _repository_identity(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CaseEvidenceRelationshipError("source_repository_invalid")
    value = value.strip()
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc:
        if (
            parsed.scheme not in ("https", "http")
            or parsed.netloc.lower() not in {"github.com", "www.github.com"}
            or parsed.params
            or parsed.query
            or parsed.fragment
        ):
            raise CaseEvidenceRelationshipError("source_repository_not_supported_canonical_url")
        path = parsed.path.strip("/")
    else:
        # Short owner/repository notation is accepted for case records, but
        # URL delimiters and percent-encoded path components are never aliases.
        if any(char in value for char in "?#%"):
            raise CaseEvidenceRelationshipError("source_repository_invalid")
        path = value.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    parts = path.split("/")
    component_re = re.compile(r"^[A-Za-z0-9_.-]+$")
    if (
        len(parts) != 2
        or any(
            not part
            or part in {".", ".."}
            or not component_re.fullmatch(part)
            for part in parts
        )
    ):
        raise CaseEvidenceRelationshipError("source_repository_invalid")
    return "/".join(part.lower() for part in parts)


def _declared_report_commits(report: Mapping[str, Any]) -> set[str]:
    commits: set[str] = set()
    direct = report.get("source_commit")
    if isinstance(direct, str):
        commits.add(direct)
    source_revision = report.get("source_revision")
    if isinstance(source_revision, dict) and isinstance(source_revision.get("commit"), str):
        commits.add(source_revision["commit"])
    comparison = report.get("source_comparison")
    if isinstance(comparison, dict):
        for revision in comparison.values():
            if isinstance(revision, dict) and isinstance(revision.get("commit"), str):
                commits.add(revision["commit"])
    return commits


def validate_case_evidence_relationship(
    case: Mapping[str, Any],
    relationship: Mapping[str, Any],
    source_report_bytes: bytes,
) -> dict[str, str]:
    """Validate relation fields against case identity and the exact report bytes.

    EXACT_TARGET_REVISION requires explicit top-level source_repository/source_commit
    in the report. CONTEXTUAL_BENCHMARK may point to a revision explicitly declared
    by a report's source_revision or source_comparison entries.
    """
    if not isinstance(case, Mapping):
        raise CaseEvidenceRelationshipError("case_must_be_object")
    if not isinstance(relationship, Mapping):
        raise CaseEvidenceRelationshipError("relationship_must_be_object")
    if set(relationship) != RELATIONSHIP_FIELDS:
        missing = sorted(RELATIONSHIP_FIELDS - set(relationship))
        extra = sorted(set(relationship) - RELATIONSHIP_FIELDS)
        raise CaseEvidenceRelationshipError(
            "relationship_schema_mismatch:missing=" + ",".join(missing)
            + ";extra=" + ",".join(extra)
        )
    version = relationship.get("schema_version")
    if type(version) is not int or version != SCHEMA_VERSION:
        raise CaseEvidenceRelationshipError("relationship_schema_version_unsupported")
    relationship_type = relationship.get("relationship_type")
    if not isinstance(relationship_type, str) or relationship_type not in RELATIONSHIP_TYPES:
        raise CaseEvidenceRelationshipError("relationship_type_invalid")
    if not isinstance(source_report_bytes, bytes) or not source_report_bytes:
        raise CaseEvidenceRelationshipError("source_report_bytes_required")
    if len(source_report_bytes) > MAX_SOURCE_REPORT_BYTES:
        raise CaseEvidenceRelationshipError("source_report_size_limit_exceeded")

    try:
        report = json.loads(
            source_report_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                CaseEvidenceRelationshipError("source_report_non_finite_number")
            ),
        )
    except CaseEvidenceRelationshipError:
        raise
    except RecursionError as exc:
        raise CaseEvidenceRelationshipError("source_report_nesting_limit_exceeded") from exc
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CaseEvidenceRelationshipError("source_report_invalid_json") from exc
    if not isinstance(report, dict):
        raise CaseEvidenceRelationshipError("source_report_must_be_object")

    if relationship.get("case_id") != case.get("case_id"):
        raise CaseEvidenceRelationshipError("case_id_mismatch")
    expected_case_digest = immutable_case_contract_sha256(case)
    supplied_case_digest = relationship.get("case_contract_sha256")
    if not isinstance(supplied_case_digest, str) or not SHA256_RE.fullmatch(supplied_case_digest):
        raise CaseEvidenceRelationshipError("case_contract_sha256_invalid")
    if supplied_case_digest != expected_case_digest:
        raise CaseEvidenceRelationshipError("case_contract_digest_mismatch")

    report_id = report.get("report_id")
    experiment_id = report.get("experiment_id")
    if not isinstance(report_id, str) or not report_id or relationship.get("report_id") != report_id:
        raise CaseEvidenceRelationshipError("report_id_mismatch")
    if not isinstance(experiment_id, str) or not experiment_id or relationship.get("experiment_id") != experiment_id:
        raise CaseEvidenceRelationshipError("experiment_id_mismatch")

    report_repository = report.get("source_repository", report.get("upstream_repository"))
    if _repository_identity(relationship.get("source_repository")) != _repository_identity(report_repository):
        raise CaseEvidenceRelationshipError("source_repository_mismatch")
    source_commit = relationship.get("source_commit")
    if not isinstance(source_commit, str) or not COMMIT_RE.fullmatch(source_commit):
        raise CaseEvidenceRelationshipError("source_commit_must_be_full_lowercase_sha")
    report_digest = hashlib.sha256(source_report_bytes).hexdigest()
    if relationship.get("source_report_sha256") != report_digest:
        raise CaseEvidenceRelationshipError("source_report_digest_mismatch")

    relation_type = relationship["relationship_type"]
    if relation_type == EXACT_TARGET_REVISION:
        if not isinstance(report.get("source_repository"), str) or not isinstance(report.get("source_commit"), str):
            raise CaseEvidenceRelationshipError("exact_target_report_requires_explicit_source_identity")
        if _repository_identity(case.get("target_repository")) != _repository_identity(report["source_repository"]):
            raise CaseEvidenceRelationshipError("target_repository_mismatch")
        target_commit = case.get("target_commit")
        if not isinstance(target_commit, str) or not COMMIT_RE.fullmatch(target_commit):
            raise CaseEvidenceRelationshipError("target_commit_invalid")
        if source_commit != report["source_commit"] or source_commit != target_commit:
            raise CaseEvidenceRelationshipError("target_commit_mismatch")
    else:
        if source_commit not in _declared_report_commits(report):
            raise CaseEvidenceRelationshipError("contextual_commit_not_declared_by_report")

    return {
        "case_contract_sha256": expected_case_digest,
        "source_report_sha256": report_digest,
        "relationship_type": relation_type,
        "report_id": report_id,
        "experiment_id": experiment_id,
    }