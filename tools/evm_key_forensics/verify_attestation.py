"""Verify a downloaded EVM Key Forensics archive with the GitHub CLI.

This is a thin acceptance wrapper around `gh attestation verify`. It checks the
verified statement's subject digest and workflow identity against caller-supplied
expectations and the run metadata embedded in the archive. It does not prove that
the workflow or runner was honest, nor does it establish historical vulnerability
reproduction.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path

WORKFLOW_REPOSITORY = "rudimentall1/AegisForge"
WORKFLOW_NAME = "EVM Key Forensics Probe"
WORKFLOW_PATH = ".github/workflows/evm-key-forensics-probe.yml"
ARCHIVE_MEMBER = "complete-evidence/probe-evidence/probe-run-metadata.json"
MAX_ARCHIVE_BYTES = 140 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 16
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_ATTESTATION_REPORT_BYTES = 8 * 1024 * 1024


def _reject_duplicate_json_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_json_key:" + key)
        value[key] = item
    return value


def _reject_nonstandard_json_constant(value):
    raise ValueError("nonstandard_json_constant:" + value)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(chunk)
            # Re-check the actual bytes read. The earlier stat() check can race
            # with a file replacement or growth before hashing begins.
            if total > MAX_ARCHIVE_BYTES:
                raise ValueError("archive_exceeds_size_limit")
            digest.update(chunk)
    return digest.hexdigest()


def _read_metadata(archive_path: Path) -> dict:
    if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("archive_exceeds_size_limit")
    with zipfile.ZipFile(archive_path, "r") as archive:
        infos = archive.infolist()
        if len(infos) > MAX_ARCHIVE_MEMBERS:
            raise ValueError("archive_member_count_exceeded")
        names = [item.filename for item in infos]
        if len(names) != len(set(names)):
            raise ValueError("archive_duplicate_member")
        try:
            info = archive.getinfo(ARCHIVE_MEMBER)
        except KeyError as exc:
            raise ValueError("probe_metadata_missing") from exc
        if info.file_size > MAX_METADATA_BYTES:
            raise ValueError("probe_metadata_exceeds_size_limit")
        if info.flag_bits & 0x1:
            raise ValueError("encrypted_metadata_not_supported")
        raw = archive.read(info)
        if len(raw) != info.file_size:
            raise ValueError("probe_metadata_size_mismatch")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
    if not isinstance(value, dict):
        raise ValueError("probe_metadata_must_be_object")
    return value


def verify_attestation(
    archive_path: Path,
    *,
    expected_sha: str,
    expected_ref: str,
    expected_run_id: str,
    expected_attempt: str,
    gh_output: str | None = None,
) -> dict:
    if archive_path.is_symlink() or not archive_path.is_file():
        raise ValueError("archive_must_be_regular_file")

    if gh_output is None:
        try:
            result = subprocess.run(
                [
                    "gh", "attestation", "verify", str(archive_path),
                    "--repo", WORKFLOW_REPOSITORY, "--format", "json",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError as exc:
            raise ValueError("github_cli_not_installed") from exc
        except subprocess.TimeoutExpired as exc:
            raise ValueError("github_cli_attestation_verification_timed_out") from exc
        if result.returncode != 0:
            raise ValueError("github_cli_attestation_verification_failed")
        gh_output = result.stdout

    if len(gh_output.encode("utf-8")) > MAX_ATTESTATION_REPORT_BYTES:
        raise ValueError("attestation_report_exceeds_size_limit")
    try:
        report = json.loads(
            gh_output,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonstandard_json_constant,
        )
    except RecursionError as exc:
        raise ValueError("attestation_report_nesting_limit_exceeded") from exc
    if not isinstance(report, list) or not report:
        raise ValueError("github_cli_returned_no_verified_attestations")

    metadata = _read_metadata(archive_path)
    archive_sha = _sha256(archive_path)
    expected_metadata = {
        "git_commit": expected_sha,
        "github_sha": expected_sha,
        "github_ref": expected_ref,
        "github_run_id": expected_run_id,
        "github_run_attempt": expected_attempt,
    }
    if any(metadata.get(key) != value for key, value in expected_metadata.items()):
        raise ValueError("archive_metadata_does_not_match_expected_run")

    matched = False
    for item in report:
        if not isinstance(item, dict):
            continue
        result = item.get("verificationResult", {})
        if not isinstance(result, dict):
            continue
        signature = result.get("signature", {})
        certificate = signature.get("certificate", {}) if isinstance(signature, dict) else {}
        statement = result.get("statement", {})
        if not isinstance(statement, dict):
            continue
        predicate = statement.get("predicate", {})
        if not isinstance(predicate, dict):
            continue
        build_definition = predicate.get("buildDefinition", {})
        if not isinstance(build_definition, dict):
            continue
        external_parameters = build_definition.get("externalParameters", {})
        if not isinstance(external_parameters, dict):
            continue
        workflow = external_parameters.get("workflow", {})
        run_details = predicate.get("runDetails", {})
        run_metadata = run_details.get("metadata", {}) if isinstance(run_details, dict) else {}
        expected_invocation_id = (
            f"https://github.com/{WORKFLOW_REPOSITORY}/actions/runs/"
            f"{expected_run_id}/attempts/{expected_attempt}"
        )
        invocation_matches = (
            isinstance(run_metadata, dict)
            and run_metadata.get("invocationId") == expected_invocation_id
        )
        subjects = statement.get("subject", [])
        subject_matches = isinstance(subjects, list) and any(
            isinstance(subject, dict)
            and subject.get("name") == archive_path.name
            and isinstance(subject.get("digest"), dict)
            and subject.get("digest", {}).get("sha256") == archive_sha
            for subject in subjects
        )
        if (
            isinstance(certificate, dict)
            and certificate.get("githubWorkflowRepository") == WORKFLOW_REPOSITORY
            and certificate.get("githubWorkflowName") == WORKFLOW_NAME
            and certificate.get("githubWorkflowSHA") == expected_sha
            and certificate.get("githubWorkflowRef") == expected_ref
            and isinstance(workflow, dict)
            and workflow.get("path") == WORKFLOW_PATH
            and workflow.get("repository") == "https://github.com/" + WORKFLOW_REPOSITORY
            and workflow.get("ref") == expected_ref
            and invocation_matches
            and subject_matches
        ):
            matched = True
            break

    if not matched:
        raise ValueError("verified_attestation_identity_or_subject_mismatch")

    return {
        "conclusion": "PASS",
        "repository": WORKFLOW_REPOSITORY,
        "workflow": WORKFLOW_PATH,
        "workflow_sha": expected_sha,
        "workflow_ref": expected_ref,
        "run_id": expected_run_id,
        "run_attempt": expected_attempt,
        "subject": archive_path.name,
        "subject_sha256": archive_sha,
        "verified_attestations_examined": len(report),
        "historical_vulnerability": "INCONCLUSIVE",
        "historical_source_to_binary_provenance": "NOT_ESTABLISHED",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--expected-ref", required=True)
    parser.add_argument("--expected-run-id", required=True)
    parser.add_argument("--expected-attempt", required=True)
    args = parser.parse_args(argv)
    try:
        result = verify_attestation(
            args.archive,
            expected_sha=args.expected_sha,
            expected_ref=args.expected_ref,
            expected_run_id=args.expected_run_id,
            expected_attempt=args.expected_attempt,
        )
    except (OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile, subprocess.SubprocessError) as exc:
        print(json.dumps({"conclusion": "FAIL", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
