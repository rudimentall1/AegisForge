#!/usr/bin/env python3
"""Validate the source evidence dossier's schema and pinned-source invariants."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

PINNED = {
    "pre-disclosure": {
        "commit": "0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6",
        "blob": "c9226fc02a52633a84664cbf3aaf2b4af8a59b25",
    },
    "post-disclosure-archive": {
        "commit": "186b9b27ab3e24a1899f648adcabcbf0e5f3131e",
        "blob": "884ced30ed6e55794ea5bda0451b52e81ddec1dd",
    },
}
MAX_DOSSIER_BYTES = 2 * 1024 * 1024

EXPECTED_SUPPORTING_REFERENCES = [
    {
        "type": "issue",
        "label": "Original report: Private key safety",
        "url": "https://github.com/johguse/profanity/issues/61",
        "evidentiary_role": "Historical report and hypothesis; not an independent reproduction",
    },
    {
        "type": "security_disclosure",
        "label": "1inch security write-up",
        "url": "https://blog.1inch.io/a-vulnerability-disclosed-in-profanity-an-ethereum-vanity-address-tool-68ed7455fc8c",
        "evidentiary_role": "External disclosure context; does not establish this repository's own reproduction",
    },
]

REQUIRED_TOP_LEVEL = {
    "schema_version", "dossier_id", "status", "artifact_context",
    "reviewed_upstream", "claim_register", "verification_contract",
    "experiment_state", "promotion_rules",
}


def _pairs_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate_json_key:{key}")
        result[key] = value
    return result


def validate_dossier(data: object) -> list[str]:
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["root_must_be_object"]
    missing = sorted(REQUIRED_TOP_LEVEL - data.keys())
    extra = sorted(data.keys() - REQUIRED_TOP_LEVEL)
    if missing:
        errors.append("missing_top_level_fields:" + ",".join(missing))
    if extra:
        errors.append("unexpected_top_level_fields:" + ",".join(extra))
    if data.get("schema_version") != 1 or isinstance(data.get("schema_version"), bool):
        errors.append("unsupported_schema_version")
    if data.get("dossier_id") != "evm-key-forensics-profanity-source-evidence-v1":
        errors.append("unexpected_dossier_id")
    if data.get("status") != "SOURCE_REVIEW_ONLY":
        errors.append("dossier_status_must_remain_source_review_only")
    if data.get("artifact_context") != (
        "HISTORICAL_SOURCE_REVIEW_BASELINE; branch names are mutable labels, not provenance"
    ):
        errors.append("artifact_context_must_not_claim_branch_provenance")

    upstream = data.get("reviewed_upstream")
    if not isinstance(upstream, dict):
        errors.append("reviewed_upstream_must_be_object")
        upstream = {}
    if upstream.get("repository") != "https://github.com/johguse/profanity":
        errors.append("unexpected_upstream_repository")
    if upstream.get("supporting_references") != EXPECTED_SUPPORTING_REFERENCES:
        errors.append("supporting_references_mismatch")
    files = upstream.get("files")
    if not isinstance(files, list) or len(files) != len(PINNED):
        errors.append("pinned_source_file_count_mismatch")
        files = []
    seen_roles = set()
    for item in files:
        if not isinstance(item, dict):
            errors.append("source_entry_must_be_object")
            continue
        role = item.get("role")
        if not isinstance(role, str) or role not in PINNED:
            errors.append("unknown_source_role")
            continue
        if role in seen_roles:
            errors.append("duplicate_source_role:" + role)
        seen_roles.add(role)
        pin = PINNED[role]
        if item.get("commit") != pin["commit"]:
            errors.append("pinned_commit_mismatch:" + role)
        if item.get("git_blob_sha1") != pin["blob"]:
            errors.append("pinned_blob_mismatch:" + role)
        if item.get("path") != "Dispatcher.cpp":
            errors.append("unexpected_source_path:" + role)
        expected_url = f"https://github.com/johguse/profanity/blob/{pin['commit']}/Dispatcher.cpp"
        if item.get("url") != expected_url:
            errors.append("immutable_source_url_mismatch:" + role)
    if seen_roles != set(PINNED):
        errors.append("pinned_source_roles_incomplete")

    claims = data.get("claim_register")
    required_claims = {"SRC-001", "SRC-002"}
    if not isinstance(claims, list):
        errors.append("claim_register_must_be_list")
        claims = []
    claim_ids = [x.get("id") for x in claims if isinstance(x, dict)]
    if (
        len(claim_ids) != len(required_claims)
        or any(not isinstance(claim_id, str) for claim_id in claim_ids)
        or set(claim_ids) != required_claims
    ):
        errors.append("claim_register_ids_mismatch")
    expected_claims = {
        "SRC-001": {
            "claim": "The reviewed function initializes mt19937_64 from one random_device result and derives four distribution outputs from that engine.",
            "evidence_level": "E0_SOURCE_INSPECTION",
            "status": "SUPPORTED_BY_PINNED_SOURCE_PATTERN_CHECK",
        },
        "SRC-002": {
            "claim": "The pre-disclosure and post-disclosure pinned Dispatcher.cpp files match the expected Git blob identifiers.",
            "evidence_level": "SOURCE_IDENTITY",
            "status": "CHECKED_BY_SOURCE_PATTERN_CLI",
        },
    }
    for claim in claims:
        if not isinstance(claim, dict):
            errors.append("claim_entry_must_be_object")
            continue
        claim_id = claim.get("id")
        if not isinstance(claim_id, str) or claim_id not in expected_claims:
            errors.append("claim_content_unrecognized")
        else:
            for field, expected_value in expected_claims[claim_id].items():
                if claim.get(field) != expected_value:
                    errors.append(f"claim_content_mismatch:{claim_id}:{field}")
        boundaries = claim.get("does_not_establish")
        if (
            not isinstance(boundaries, list)
            or not boundaries
            or not all(isinstance(item, str) and item.strip() for item in boundaries)
        ):
            errors.append("claim_boundaries_required:" + str(claim_id))

    contract = data.get("verification_contract")
    if not isinstance(contract, dict):
        errors.append("verification_contract_must_be_object")
        contract = {}
    if contract.get("checker") != "tools/evm_key_forensics/check_historical_source_pattern.py":
        errors.append("verification_checker_path_mismatch")
    expected_checker_behavior = [
        "Reads a locally supplied source file with a fixed size bound",
        "Checks the exact expected Git blob SHA-1 for the selected pinned revision",
        "Emits SHA-256 for the exact bytes inspected",
        "Rejects missing, ambiguous, malformed, or mismatched source as INCONCLUSIVE",
    ]
    if contract.get("checker_behavior") != expected_checker_behavior:
        errors.append("verification_checker_behavior_mismatch")
    if contract.get("independent_retrieval_recommended") is not True:
        errors.append("independent_source_retrieval_must_be_recommended")
    if contract.get("source_to_binary_provenance") != "NOT_ESTABLISHED":
        errors.append("source_to_binary_provenance_must_not_be_overstated")
    if contract.get("source_review_runner_attestation") != "NOT_IMPLEMENTED":
        errors.append("source_review_runner_attestation_must_remain_not_implemented")
    if contract.get("evidence_package_github_attestation") != (
        "PUBLISHED_BY_SEPARATE_WORKFLOW; DOES_NOT_AUTHENTICATE_SOURCE_CLAIMS"
    ):
        errors.append("evidence_package_attestation_scope_must_be_explicit")
    if contract.get("signed_dossier") is not False:
        errors.append("dossier_signing_status_mismatch")

    state = data.get("experiment_state")
    if not isinstance(state, dict):
        errors.append("experiment_state_must_be_object")
        state = {}
    required_false = (
        "historical_code_executed",
        "wallet_material_used",
        "historical_vulnerability_reproduced",
    )
    for key in required_false:
        if state.get(key) is not False:
            errors.append("unsafe_or_unsubstantiated_state:" + key)
    if state.get("independent_review") != "PENDING":
        errors.append("independent_review_must_remain_pending")
    if state.get("overall_conclusion") != "INCONCLUSIVE":
        errors.append("overall_conclusion_must_remain_inconclusive")
    rules = data.get("promotion_rules")
    if not isinstance(rules, list) or len(rules) < 3 or not all(isinstance(x, str) and x.strip() for x in rules):
        errors.append("promotion_rules_incomplete")
    return errors


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dossier", type=Path)
    args = parser.parse_args(argv)
    try:
        with args.dossier.open("rb") as stream:
            raw = stream.read(MAX_DOSSIER_BYTES + 1)
        if len(raw) > MAX_DOSSIER_BYTES:
            raise ValueError("dossier_exceeds_size_limit")
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs_no_duplicates)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({"valid": False, "errors": [f"invalid_dossier:{type(exc).__name__}:{exc}"]}, sort_keys=True))
        return 2
    errors = validate_dossier(data)
    print(json.dumps({"valid": not errors, "errors": errors}, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
