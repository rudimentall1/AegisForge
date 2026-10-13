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
    if data.get("conclusion") != "SOURCE_PATTERN_MATCHED":
        errors.append(f"{role}:source_pattern_not_matched")
    if data.get("errors") != []:
        errors.append(f"{role}:checker_reported_errors")
    for field in ("historical_code_executed", "wallet_material_used", "historical_vulnerability_reproduced"):
        if data.get(field) is not False:
            errors.append(f"{role}:unsafe_or_unsubstantiated_flag:{field}")
    return errors


def build_report(pre: dict, post: dict) -> dict:
    errors = _validate_result(pre, "pre-disclosure") + _validate_result(post, "post-disclosure")
    return {
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
                "checker_conclusion": pre.get("conclusion"),
                "validated": not any(e.startswith("pre-disclosure:") for e in errors),
            },
            "post_disclosure_archive": {
                "commit": EXPECTED["post-disclosure"]["commit"],
                "git_blob_sha1": EXPECTED["post-disclosure"]["blob"],
                "source_sha256": post.get("source_sha256"),
                "checker_conclusion": post.get("conclusion"),
                "validated": not any(e.startswith("post-disclosure:") for e in errors),
            },
            "same_source_sha256": (
                pre.get("source_sha256") == post.get("source_sha256")
                if isinstance(pre.get("source_sha256"), str) and isinstance(post.get("source_sha256"), str)
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
            "trusted_runner_attestation": "NOT_IMPLEMENTED",
            "independent_review": "PENDING",
        },
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pre_disclosure", type=Path)
    parser.add_argument("post_disclosure", type=Path)
    parser.add_argument("--output", type=Path, help="write report to this path; stdout if omitted")
    args = parser.parse_args(argv)
    try:
        report = build_report(_load_result(args.pre_disclosure), _load_result(args.post_disclosure))
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
