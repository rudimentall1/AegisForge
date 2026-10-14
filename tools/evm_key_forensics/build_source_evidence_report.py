#!/usr/bin/env python3
"""Reconcile pinned source-pattern results without promoting them to exploit proof."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

EXPECTED = {
    "pre-disclosure": {
        "commit": "0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6",
        "blob": "c9226fc02a52633a84664cbf3aaf2b4af8a59b25",
    },
    "post-disclosure": {
        "commit": "186b9b27ab3e24a1899f648adcabcbf0e5f3131e",
        "blob": "884ced30ed6e55794ea5bda0451b52e81ddec1dd",
    },
}
REPOSITORY = "https://github.com/johguse/profanity"
EXPERIMENT_ID = "evm-forensics-historical-source-pattern-v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate_json_key:{key}")
        result[key] = value
    return result


def _load_result(path: Path) -> dict:
    raw = path.read_bytes()
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("input_exceeds_size_limit")
    data = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    if not isinstance(data, dict):
        raise ValueError("input_root_must_be_object")
    return data


def _validate_result(data: dict, role: str) -> list[str]:
    errors = []
    pin = EXPECTED[role]
    if data.get("schema_version") != 1 or isinstance(data.get("schema_version"), bool):
        errors.append(f"{role}:unsupported_schema_version")
    if data.get("experiment_id") != EXPERIMENT_ID:
        errors.append(f"{role}:unexpected_experiment_id")
    if data.get("upstream_repository") != REPOSITORY:
        errors.append(f"{role}:unexpected_upstream_repository")
    if data.get("source_revision_role") != role:
        errors.append(f"{role}:source_revision_role_mismatch")
    if data.get("expected_upstream_commit") != pin["commit"]:
        errors.append(f"{role}:pinned_commit_mismatch")
    if data.get("git_blob_sha1") != pin["blob"] or data.get("pinned_source_blob_matches") is not True:
        errors.append(f"{role}:pinned_source_blob_not_verified")
    if not isinstance(data.get("source_sha256"), str) or not SHA256_RE.fullmatch(data["source_sha256"]):
        errors.append(f"{role}:invalid_source_sha256")
    if not isinstance(data.get("function_body_sha256"), str) or not SHA256_RE.fullmatch(data["function_body_sha256"]):
        errors.append(f"{role}:invalid_function_body_sha256")
    if data.get("conclusion") != "SOURCE_PATTERN_MATCHED":
        errors.append(f"{role}:source_pattern_not_matched")
    if data.get("errors") != []:
        errors.append(f"{role}:checker_reported_errors")
    for field in ("historical_code_executed", "wallet_material_used", "historical_vulnerability_reproduced"):
        if data.get(field) is not False:
            errors.append(f"{role}:unsafe_or_unsubstantiated_flag:{field}")
    return errors


def build_report(pre: dict, post: dict, reproducibility: dict | None = None) -> dict:
    errors = _validate_result(pre, "pre-disclosure") + _validate_result(post, "post-disclosure")
    report = {
        "schema_version": 1,
        "report_id": "evm-key-forensics-profanity-source-comparison-v1",
        "experiment_id": EXPERIMENT_ID,
        "upstream_repository": REPOSITORY,
        "evidence_class": "PINNED_SOURCE_PATTERN_INSPECTION",
        "overall_conclusion": "INCONCLUSIVE",
        "source_comparison": {
            "pre_disclosure": {
                "commit": EXPECTED["pre-disclosure"]["commit"],
                "git_blob_sha1": EXPECTED["pre-disclosure"]["blob"],
                "source_sha256": pre.get("source_sha256"),
                "function_body_sha256": pre.get("function_body_sha256"),
                "checker_conclusion": pre.get("conclusion"),
                "validated": not any(e.startswith("pre-disclosure:") for e in errors),
            },
            "post_disclosure_archive": {
                "commit": EXPECTED["post-disclosure"]["commit"],
                "git_blob_sha1": EXPECTED["post-disclosure"]["blob"],
                "source_sha256": post.get("source_sha256"),
                "function_body_sha256": post.get("function_body_sha256"),
                "checker_conclusion": post.get("conclusion"),
                "validated": not any(e.startswith("post-disclosure:") for e in errors),
            },
            "same_source_sha256": (
                pre.get("source_sha256") == post.get("source_sha256")
                if isinstance(pre.get("source_sha256"), str) and isinstance(post.get("source_sha256"), str)
                else None
            ),
            "same_create_seed_function_body_sha256": (
                pre.get("function_body_sha256") == post.get("function_body_sha256")
                if isinstance(pre.get("function_body_sha256"), str)
                and isinstance(post.get("function_body_sha256"), str)
                else None
            ),
            "same_git_blob_sha1": (
                pre.get("git_blob_sha1") == post.get("git_blob_sha1")
                if isinstance(pre.get("git_blob_sha1"), str) and isinstance(post.get("git_blob_sha1"), str)
                else None
            ),
        },
        "validation_errors": errors,
        "interpretation": (
            "The report reconciles source-pattern checker outputs for two pinned source revisions. "
            "A matching pattern is source-inspection evidence only; it does not establish runtime "
            "entropy, exploitability, key predictability, wallet exposure, or historical vulnerability reproduction."
        ),
        "limitations": {
            "historical_code_executed": False,
            "wallet_material_used": False,
            "historical_vulnerability_reproduced": False,
            "source_to_binary_provenance": "NOT_ESTABLISHED",
            "source_review_runner_attestation": "NOT_IMPLEMENTED",
            "evidence_package_github_attestation": "CHECKED_BY_SEPARATE_WORKFLOW_STEP; DOES_NOT_AUTHENTICATE_SOURCE_CLAIMS",
            "independent_review": "PENDING",
        },
    }
    if reproducibility is not None:
        report["reproducibility"] = reproducibility
    return report


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pre_disclosure", type=Path)
    parser.add_argument("post_disclosure", type=Path)
    parser.add_argument("--output", type=Path, help="write report to this path; stdout if omitted")
    args = parser.parse_args(argv)
    try:
        pre_raw = args.pre_disclosure.read_bytes()
        post_raw = args.post_disclosure.read_bytes()
        if len(pre_raw) > 2 * 1024 * 1024 or len(post_raw) > 2 * 1024 * 1024:
            raise ValueError("input_exceeds_size_limit")
        pre = json.loads(pre_raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
        post = json.loads(post_raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
        if not isinstance(pre, dict) or not isinstance(post, dict):
            raise ValueError("input_root_must_be_object")
        checker_path = Path(__file__).with_name("check_historical_source_pattern.py")
        reproducibility = {
            "input_checker_result_sha256": {
                "pre_disclosure": _sha256_bytes(pre_raw),
                "post_disclosure": _sha256_bytes(post_raw),
            },
            "checker_script_sha256": hashlib.sha256(checker_path.read_bytes()).hexdigest(),
            "report_builder_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "hashes_are_authenticity_proof": False,
        }
        report = build_report(pre, post, reproducibility=reproducibility)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        print(json.dumps({"valid": False, "errors": [f"invalid_checker_input:{type(exc).__name__}:{exc}"]}, sort_keys=True))
        return 2
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        try:
            args.output.write_text(rendered, encoding="utf-8")
        except OSError as exc:
            print(json.dumps({"valid": False, "errors": [f"report_write_failed:{type(exc).__name__}"]}, sort_keys=True))
            return 2
    else:
        print(rendered, end="")
    return 0 if not report["validation_errors"] else 2


if __name__ == "__main__":
    sys.exit(main())
