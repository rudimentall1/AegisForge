"""Strict semantic schema checks for the pinned historical source report."""
from __future__ import annotations

TOP_LEVEL = {
    "schema_version", "report_id", "experiment_id", "upstream_repository",
    "evidence_class", "overall_conclusion", "source_comparison",
    "validation_errors", "interpretation", "limitations", "reproducibility",
}
COMPARISON_FIELDS = {
    "pre_disclosure", "post_disclosure_archive", "same_source_sha256",
    "same_create_seed_function_body_sha256", "same_git_blob_sha1",
}
REVISION_FIELDS = {
    "commit", "git_blob_sha1", "source_sha256", "function_body_sha256",
    "checker_conclusion", "validated",
}
LIMITATION_FIELDS = {
    "historical_code_executed", "wallet_material_used",
    "historical_vulnerability_reproduced", "source_to_binary_provenance",
    "source_review_runner_attestation", "evidence_package_github_attestation",
    "independent_review",
}
REPRODUCIBILITY_FIELDS = {
    "input_checker_result_sha256", "checker_script_sha256",
    "report_builder_sha256", "hashes_are_authenticity_proof",
}

def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)

def validate_source_report_schema(report: object) -> bool:
    if not isinstance(report, dict) or set(report) - TOP_LEVEL:
        return False
    if not (TOP_LEVEL - {"reproducibility"}) <= set(report):
        return False
    if (type(report.get("schema_version")) is not int or report["schema_version"] != 1
        or report.get("report_id") != "evm-key-forensics-profanity-source-comparison-v1"
        or report.get("experiment_id") != "evm-forensics-historical-source-pattern-v1"
        or report.get("upstream_repository") != "https://github.com/johguse/profanity"
        or report.get("evidence_class") != "PINNED_SOURCE_PATTERN_INSPECTION"
        or report.get("overall_conclusion") != "INCONCLUSIVE"
        or report.get("validation_errors") != []):
        return False
    comparison = report.get("source_comparison")
    if not isinstance(comparison, dict) or set(comparison) != COMPARISON_FIELDS:
        return False
    expected = {
        "pre_disclosure": ("0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6", "c9226fc02a52633a84664cbf3aaf2b4af8a59b25"),
        "post_disclosure_archive": ("186b9b27ab3e24a1899f648adcabcbf0e5f3131e", "884ced30ed6e55794ea5bda0451b52e81ddec1dd"),
    }
    for name, (commit, blob) in expected.items():
        revision = comparison.get(name)
        if not isinstance(revision, dict) or set(revision) != REVISION_FIELDS:
            return False
        if (revision.get("commit") != commit or revision.get("git_blob_sha1") != blob
            or revision.get("checker_conclusion") != "SOURCE_PATTERN_MATCHED"
            or revision.get("validated") is not True
            or not _is_sha256(revision.get("source_sha256"))
            or not _is_sha256(revision.get("function_body_sha256"))):
            return False
    expected_comparisons = {
        "same_source_sha256": comparison["pre_disclosure"]["source_sha256"] == comparison["post_disclosure_archive"]["source_sha256"],
        "same_create_seed_function_body_sha256": comparison["pre_disclosure"]["function_body_sha256"] == comparison["post_disclosure_archive"]["function_body_sha256"],
        "same_git_blob_sha1": comparison["pre_disclosure"]["git_blob_sha1"] == comparison["post_disclosure_archive"]["git_blob_sha1"],
    }
    if any(type(comparison.get(key)) is not bool or comparison[key] is not value for key, value in expected_comparisons.items()):
        return False
    if report.get("interpretation") != ("The report reconciles source-pattern checker outputs for two pinned source revisions. A matching pattern is source-inspection evidence only; it does not establish runtime entropy, exploitability, key predictability, wallet exposure, or historical vulnerability reproduction."):
        return False
    limitations = report.get("limitations")
    if not isinstance(limitations, dict) or set(limitations) != LIMITATION_FIELDS:
        return False
    if any(limitations.get(key) is not False for key in ("historical_code_executed", "wallet_material_used", "historical_vulnerability_reproduced")):
        return False
    if (limitations.get("source_to_binary_provenance") != "NOT_ESTABLISHED"
        or limitations.get("source_review_runner_attestation") != "NOT_IMPLEMENTED"
        or limitations.get("independent_review") != "PENDING"
        or limitations.get("evidence_package_github_attestation") != "CHECKED_BY_SEPARATE_WORKFLOW_STEP; DOES_NOT_AUTHENTICATE_SOURCE_CLAIMS"):
        return False
    if "reproducibility" in report:
        reproducibility = report["reproducibility"]
        if not isinstance(reproducibility, dict) or set(reproducibility) != REPRODUCIBILITY_FIELDS:
            return False
        hashes = reproducibility.get("input_checker_result_sha256")
        if (not isinstance(hashes, dict) or set(hashes) != {"pre_disclosure", "post_disclosure"}
            or not all(_is_sha256(value) for value in hashes.values())
            or not _is_sha256(reproducibility.get("checker_script_sha256"))
            or not _is_sha256(reproducibility.get("report_builder_sha256"))
            or reproducibility.get("hashes_are_authenticity_proof") is not False):
            return False
    return True
