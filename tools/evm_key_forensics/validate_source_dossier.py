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

REQUIRED_TOP_LEVEL = {
    "schema_version", "dossier_id", "status", "generated_for_branch",
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
    if data.get("generated_for_branch") != "feat/evm-git-object-source-verifier":
        errors.append("unexpected_branch")

    upstream = data.get("reviewed_upstream")
    if not isinstance(upstream, dict):
        errors.append("reviewed_upstream_must_be_object")
        upstream = {}
    if upstream.get("repository") != "https://github.com/johguse/profanity":
        errors.append("unexpected_upstream_repository")
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
        if role not in PINNED:
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
    if set(claim_ids) != required_claims or len(claim_ids) != len(required_claims):
        errors.append("claim_register_ids_mismatch")
    for claim in claims:
        if not isinstance(claim, dict):
            errors.append("claim_entry_must_be_object")
            continue
        if not isinstance(claim.get("does_not_establish"), list) or not claim["does_not_establish"]:
            errors.append("claim_boundaries_required:" + str(claim.get("id")))

    contract = data.get("verification_contract")
    if not isinstance(contract, dict):
        errors.append("verification_contract_must_be_object")
        contract = {}
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
