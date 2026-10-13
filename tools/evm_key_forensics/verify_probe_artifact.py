"""Offline verifier for an exported EVM Key Forensics probe artifact.

This verifies file hashes and metadata consistency only. It does not prove entropy,
runner honesty, historical vulnerability reproduction, or wallet compromise.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate_json_key:{key}")
        result[key] = value
    return result


def _reject_nonstandard_constant(value):
    raise ValueError(f"nonstandard_json_constant:{value}")


# Probe manifests are expected to be small. Bound untrusted JSON before
# decoding so verification cannot be used to force an unbounded allocation.
MAX_JSON_FILE_BYTES = 2 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 4 * 1024 * 1024
MAX_BINARY_FILE_BYTES = 64 * 1024 * 1024


def _load_strict_json(path: Path):
    # Read at most limit + 1 bytes; checking stat() first alone would leave
    # a size-check/read race if the file changed between the two operations.
    with path.open("rb") as stream:
        raw = stream.read(MAX_JSON_FILE_BYTES + 1)
    if len(raw) > MAX_JSON_FILE_BYTES:
        raise ValueError("json_file_exceeds_size_limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("json_file_invalid_utf8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonstandard_constant,
        )
    except RecursionError as exc:
        raise ValueError("json_nesting_limit_exceeded") from exc
    if not isinstance(value, dict):
        raise ValueError("json_root_must_be_object")
    return value


def sha256(path: Path, *, max_bytes: int | None = None) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise ValueError("artifact_file_exceeds_size_limit")
            digest.update(chunk)
    return digest.hexdigest()


def _require_artifact_directory(root: Path) -> None:
    # A symlinked root can redirect every otherwise regular bundle file to a
    # different directory, so reject it before resolving any artifact paths.
    if root.is_symlink():
        raise ValueError("artifact_directory_must_not_be_symlink")
    if not root.is_dir():
        raise ValueError("artifact_directory_missing_or_not_directory")


def _require_regular_bundle_file(path: Path) -> None:
    # Do not let a bundle redirect verification to arbitrary files outside its
    # directory through symlinks. The verifier only accepts self-contained files.
    if path.is_symlink():
        raise ValueError("artifact_file_must_not_be_symlink")
    if not path.is_file():
        raise ValueError("artifact_file_missing_or_not_regular")


def verify_artifact(root: Path) -> dict:
    _require_artifact_directory(root)
    metadata_path = root / "probe-run-metadata.json"
    output_path = root / "probe-output.json"
    source_path = root / "probe-source.cpp"
    binary_path = root / "probe-binary"
    source_report_path = root / "source-evidence-report.json"
    for artifact_path in (metadata_path, output_path, source_path, binary_path, source_report_path):
        _require_regular_bundle_file(artifact_path)
    metadata = _load_strict_json(metadata_path)
    output = _load_strict_json(output_path)
    source_report = _load_strict_json(source_report_path)

    samples = output.get("samples_requested")
    distinct = output.get("distinct_values_observed")
    type_bits = output.get("random_device_result_type_bits")
    reported_entropy = output.get("random_device_reported_entropy")
    build_flags = metadata.get("build_flags")
    source_report_limitations = source_report.get("limitations")
    if not isinstance(source_report_limitations, dict):
        source_report_limitations = {}
    source_comparison = source_report.get("source_comparison")
    if not isinstance(source_comparison, dict):
        source_comparison = {}
    pre_revision = source_comparison.get("pre_disclosure")
    if not isinstance(pre_revision, dict):
        pre_revision = {}
    post_revision = source_comparison.get("post_disclosure_archive")
    if not isinstance(post_revision, dict):
        post_revision = {}
    reproducibility = source_report.get("reproducibility")
    if not isinstance(reproducibility, dict):
        reproducibility = {}
    input_hashes = reproducibility.get("input_checker_result_sha256")
    if not isinstance(input_hashes, dict):
        input_hashes = {}

    checks = {
        "schema_version_supported": type(metadata.get("schema_version")) is int and metadata.get("schema_version") == 1,
        "output_schema_supported": type(output.get("schema_version")) is int and output.get("schema_version") == 1,
        "probe_identity_matches": output.get("probe") == "std_random_device_environment_diagnostic",
        "diagnostic_only_purpose": metadata.get("purpose") == "diagnostic_environment_observation_only",
        "historical_vulnerability_not_claimed": metadata.get("historical_vulnerability_reproduced") is False,
        "entropy_not_claimed": metadata.get("entropy_proven") is False,
        "probe_does_not_claim_historical_execution": output.get("historical_profanity_code_executed") is False,
        "probe_does_not_use_wallet_material": output.get("wallet_material_used") is False,
        "sample_observations_not_entropy_proof": output.get("observations_are_entropy_proof") is False,
        "sample_count_in_bounds": type(samples) is int and 1 <= samples <= 10000,
        "distinct_count_in_bounds": type(distinct) is int and type(samples) is int and 1 <= distinct <= samples,
        "result_type_width_valid": type(type_bits) is int and type_bits > 0,
        "reported_entropy_is_finite_nonnegative": (
            type(reported_entropy) in (int, float)
            and math.isfinite(reported_entropy)
            and reported_entropy >= 0
        ),
        "source_nonempty": source_path.is_file() and source_path.stat().st_size > 0,
        "binary_nonempty": binary_path.is_file() and binary_path.stat().st_size > 0,
        "source_hash_matches": metadata.get("source_sha256") == sha256(
            source_path, max_bytes=MAX_SOURCE_FILE_BYTES
        ),
        "binary_hash_matches": metadata.get("binary_sha256") == sha256(
            binary_path, max_bytes=MAX_BINARY_FILE_BYTES
        ),
        "output_hash_matches": metadata.get("output_sha256") == sha256(
            output_path, max_bytes=MAX_JSON_FILE_BYTES
        ),
        "source_report_hash_matches": metadata.get("source_evidence_report_sha256") == sha256(
            source_report_path, max_bytes=MAX_JSON_FILE_BYTES
        ),
        "source_report_schema_supported": type(source_report.get("schema_version")) is int and source_report.get("schema_version") == 1,
        "source_report_identity_matches": (
            source_report.get("report_id") == "evm-key-forensics-profanity-source-comparison-v1"
            and source_report.get("upstream_repository") == "https://github.com/johguse/profanity"
            and source_report.get("evidence_class") == "PINNED_SOURCE_PATTERN_INSPECTION"
        ),
        "source_report_pre_revision_matches_pin": (
            pre_revision.get("commit") == "0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6"
            and pre_revision.get("git_blob_sha1") == "c9226fc02a52633a84664cbf3aaf2b4af8a59b25"
            and pre_revision.get("checker_conclusion") == "SOURCE_PATTERN_MATCHED"
            and pre_revision.get("validated") is True
        ),
        "source_report_post_revision_matches_pin": (
            post_revision.get("commit") == "186b9b27ab3e24a1899f648adcabcbf0e5f3131e"
            and post_revision.get("git_blob_sha1") == "884ced30ed6e55794ea5bda0451b52e81ddec1dd"
            and post_revision.get("checker_conclusion") == "SOURCE_PATTERN_MATCHED"
            and post_revision.get("validated") is True
        ),
        "source_report_function_fingerprints_match": (
            isinstance(pre_revision.get("function_body_sha256"), str)
            and len(pre_revision["function_body_sha256"]) == 64
            and all(char in "0123456789abcdef" for char in pre_revision["function_body_sha256"])
            and isinstance(post_revision.get("function_body_sha256"), str)
            and len(post_revision["function_body_sha256"]) == 64
            and all(char in "0123456789abcdef" for char in post_revision["function_body_sha256"])
            and source_comparison.get("same_create_seed_function_body_sha256") is True
            and pre_revision["function_body_sha256"] == post_revision["function_body_sha256"]
        ),
        "source_report_is_inconclusive": source_report.get("overall_conclusion") == "INCONCLUSIVE",
        "source_report_reproducibility_hashes_well_formed": (
            isinstance(input_hashes.get("pre_disclosure"), str)
            and len(input_hashes["pre_disclosure"]) == 64
            and all(char in "0123456789abcdef" for char in input_hashes["pre_disclosure"])
            and isinstance(input_hashes.get("post_disclosure"), str)
            and len(input_hashes["post_disclosure"]) == 64
            and all(char in "0123456789abcdef" for char in input_hashes["post_disclosure"])
            and isinstance(reproducibility.get("checker_script_sha256"), str)
            and len(reproducibility["checker_script_sha256"]) == 64
            and all(char in "0123456789abcdef" for char in reproducibility["checker_script_sha256"])
            and isinstance(reproducibility.get("report_builder_sha256"), str)
            and len(reproducibility["report_builder_sha256"]) == 64
            and all(char in "0123456789abcdef" for char in reproducibility["report_builder_sha256"])
            and reproducibility.get("hashes_are_authenticity_proof") is False
        ),
        "source_report_has_no_validation_errors": source_report.get("validation_errors") == [],
        "source_report_does_not_claim_reproduction": source_report_limitations.get("historical_vulnerability_reproduced") is False,
        "source_report_does_not_claim_source_binary_provenance": source_report_limitations.get("source_to_binary_provenance") == "NOT_ESTABLISHED",
        "commit_recorded": (
            isinstance(metadata.get("git_commit"), str)
            and len(metadata["git_commit"]) == 40
            and all(char in "0123456789abcdefABCDEF" for char in metadata["git_commit"])
        ),
        "run_id_recorded": (
            isinstance(metadata.get("github_run_id"), str)
            and metadata["github_run_id"].isdigit()
            and int(metadata["github_run_id"]) > 0
        ),
        "run_attempt_recorded": (
            isinstance(metadata.get("github_run_attempt"), str)
            and metadata["github_run_attempt"].isdigit()
            and int(metadata["github_run_attempt"]) > 0
        ),
        "runner_environment_recorded": isinstance(metadata.get("runner_os"), str) and bool(metadata["runner_os"].strip()),
        "compiler_recorded": isinstance(metadata.get("compiler_version"), str) and bool(metadata["compiler_version"].strip()),
        "build_flags_recorded": isinstance(build_flags, list) and bool(build_flags) and all(isinstance(flag, str) and flag for flag in build_flags),
    }
    integrity_verified = all(checks.values())
    return {
        "schema_version": 1,
        "integrity_verified": integrity_verified,
        # This verifier has no signature/trust-anchor input. Never present its
        # hash-consistency result as authenticated provenance.
        "authenticity": "UNTRUSTED_UNSIGNED",
        "signature_verified_against_trusted_key": False,
        "checks": checks,
        "git_commit": metadata.get("git_commit"),
        "github_run_id": metadata.get("github_run_id"),
        "limitations": [
            "Hashes prove file consistency relative to this manifest, not the truth of observations.",
            "This verifier does not authenticate who produced the artifact; authenticity is UNTRUSTED_UNSIGNED.",
            "A hash manifest alone does not authenticate runner honesty or isolation.",
            "This diagnostic is not a reproduction of historical Profanity or a vulnerability.",
        ],
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Verify an exported EVM Key Forensics probe artifact offline.")
    parser.add_argument("artifact_dir", help="Directory containing the four exported probe evidence files")
    args = parser.parse_args(argv)
    try:
        result = verify_artifact(Path(args.artifact_dir))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(json.dumps({"integrity_verified": False, "error": type(exc).__name__}, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["integrity_verified"] else 1


if __name__ == "__main__":
    sys.exit(main())
