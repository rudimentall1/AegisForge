"""Offline integrity verifier for the combined EVM Key Forensics evidence ZIP.

This validates archive safety, probe artifact hashes, and cross-run linkage. It
does not verify GitHub's separate provenance attestation; use `gh attestation
verify` for that. It does not prove historical Profanity behavior.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from tools.evm_key_forensics.verify_probe_artifact import (
    MAX_BINARY_FILE_BYTES,
    MAX_JSON_FILE_BYTES,
    MAX_SOURCE_FILE_BYTES,
    verify_artifact,
)

MAX_ARCHIVE_BYTES = 140 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 140 * 1024 * 1024
MAX_ENTRY_COUNT = 16

PROBE_FILES = {
    "probe-run-metadata.json": MAX_JSON_FILE_BYTES,
    "probe-output.json": MAX_JSON_FILE_BYTES,
    "probe-source.cpp": MAX_SOURCE_FILE_BYTES,
    "probe-binary": MAX_BINARY_FILE_BYTES,
    "probe-binary-repeat": MAX_BINARY_FILE_BYTES,
    "source-evidence-report.json": MAX_JSON_FILE_BYTES,
    "independent-source-body-review.json": MAX_JSON_FILE_BYTES,
}
EXPECTED_MEMBERS = {
    "complete-evidence/combined-evidence-index.json",
    "complete-evidence/independent-rebuild-report.json",
    *(f"complete-evidence/probe-evidence/{name}" for name in PROBE_FILES),
}


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate_json_key:{key}")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError(f"nonstandard_json_constant:{value}")


def _strict_json_bytes(raw: bytes, *, max_bytes: int = MAX_JSON_FILE_BYTES) -> dict:
    if len(raw) > max_bytes:
        raise ValueError("json_file_exceeds_size_limit")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise ValueError("json_file_invalid_utf8") from exc
    except RecursionError as exc:
        raise ValueError("json_nesting_limit_exceeded") from exc
    if not isinstance(value, dict):
        raise ValueError("json_root_must_be_object")
    return value


def _safe_member_name(name: str) -> bool:
    if not name or "\\" in name or name.startswith("/"):
        return False
    path = PurePosixPath(name)
    return not path.is_absolute() and all(part not in ("", ".", "..") for part in path.parts)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_complete_archive(archive_path: Path) -> dict:
    if archive_path.is_symlink() or not archive_path.is_file():
        raise ValueError("archive_must_be_regular_file")
    if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("archive_exceeds_size_limit")

    with zipfile.ZipFile(archive_path, "r") as archive:
        infos = archive.infolist()
        if len(infos) > MAX_ENTRY_COUNT:
            raise ValueError("archive_member_count_mismatch")
        names = [item.filename for item in infos]
        if len(names) != len(set(names)):
            raise ValueError("archive_duplicate_member")
        directory_members = {
            "complete-evidence/",
            "complete-evidence/probe-evidence/",
        }
        file_names = {item.filename for item in infos if not item.is_dir()}
        actual_directories = {item.filename for item in infos if item.is_dir()}
        if file_names != EXPECTED_MEMBERS or not actual_directories.issubset(directory_members):
            raise ValueError("archive_member_set_mismatch")

        total_uncompressed = 0
        for item in infos:
            if not _safe_member_name(item.filename):
                raise ValueError("archive_unsafe_member_path")
            mode = item.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ValueError("archive_non_regular_member")
            if item.is_dir():
                if item.filename not in {"complete-evidence/", "complete-evidence/probe-evidence/"}:
                    raise ValueError("archive_unexpected_directory")
                continue
            expected_size = None
            if item.filename.startswith("complete-evidence/probe-evidence/"):
                expected_size = PROBE_FILES[item.filename.rsplit("/", 1)[1]]
            elif item.filename.endswith(".json"):
                expected_size = MAX_JSON_FILE_BYTES
            if expected_size is None or item.file_size > expected_size:
                raise ValueError("archive_member_exceeds_size_limit")
            total_uncompressed += item.file_size
            if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
                raise ValueError("archive_uncompressed_size_limit_exceeded")
            if item.flag_bits & 0x1:
                raise ValueError("archive_encrypted_member_not_supported")
            if item.compress_size == 0 and item.file_size > 0:
                raise ValueError("archive_invalid_compression_size")
            if item.compress_size and item.file_size > item.compress_size * 1000:
                raise ValueError("archive_compression_ratio_exceeded")

        with tempfile.TemporaryDirectory(prefix="evm-key-forensics-") as temp_dir:
            root = Path(temp_dir) / "complete-evidence"
            probe_dir = root / "probe-evidence"
            probe_dir.mkdir(parents=True)
            for item in infos:
                if item.is_dir():
                    continue
                relative = PurePosixPath(item.filename).relative_to("complete-evidence")
                target = root.joinpath(*relative.parts)
                if target.is_symlink():
                    raise ValueError("archive_target_must_not_be_symlink")
                if target.exists():
                    raise ValueError("archive_duplicate_extracted_path")
                target.parent.mkdir(parents=True, exist_ok=True)
                # Stream to disk while enforcing the declared size. Never use
                # extractall() on this untrusted archive.
                written = 0
                with archive.open(item, "r") as source, target.open("xb") as dest:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > item.file_size:
                            raise ValueError("archive_member_size_overrun")
                        dest.write(chunk)
                if written != item.file_size:
                    raise ValueError("archive_member_size_mismatch")

            probe_result = verify_artifact(probe_dir)
            if not probe_result.get("integrity_verified"):
                raise ValueError("probe_artifact_integrity_failed")

            metadata = _strict_json_bytes((probe_dir / "probe-run-metadata.json").read_bytes())
            rebuild = _strict_json_bytes((root / "independent-rebuild-report.json").read_bytes())
            index = _strict_json_bytes((root / "combined-evidence-index.json").read_bytes())

            identity_fields = {
                "github_run_id": "run_id",
                "github_run_attempt": "run_attempt",
                "github_sha": "workflow_sha",
                "github_ref": "workflow_ref",
            }
            checks = {
                "index_schema_supported": type(index.get("schema_version")) is int and index.get("schema_version") == 1,
                "index_conclusion_pass": index.get("conclusion") == "PASS",
                "index_marks_cross_linkage": index.get("probe_and_rebuild_evidence_consistent") is True,
                "index_disclaims_historical_execution": index.get("historical_profanity_executed") is False,
                "index_disclaims_historical_reproduction": index.get("historical_vulnerability_reproduced") is False,
                "rebuild_report_identity": rebuild.get("check") == "independent_clean_runner_rebuild",
                "rebuild_report_pass": rebuild.get("conclusion") == "PASS",
                "rebuild_source_match": rebuild.get("source_matches") is True,
                "rebuild_binary_match": rebuild.get("binary_matches") is True,
            }
            for metadata_key, index_key in identity_fields.items():
                checks[f"index_{index_key}_matches_metadata"] = (
                    isinstance(metadata.get(metadata_key), str)
                    and metadata.get(metadata_key) == rebuild.get(metadata_key)
                    and metadata.get(metadata_key) == index.get(index_key)
                )
            hash_links = {
                "source_sha256": ("reference_source_sha256", "independent_checkout_source_sha256", "probe_source_sha256", "independent_rebuild_source_sha256"),
                "binary_sha256": ("reference_binary_sha256", "independent_rebuild_binary_sha256", "probe_binary_sha256", "independent_rebuild_binary_sha256"),
            }
            for metadata_key, fields in hash_links.items():
                values = [metadata.get(metadata_key), *(rebuild.get(key) for key in fields[:2]), *(index.get(key) for key in fields[2:])]
                checks[f"{metadata_key}_cross_run_linkage"] = (
                    all(isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value) for value in values)
                    and len(set(values)) == 1
                )
            checks["metadata_git_commit_matches_workflow_sha"] = metadata.get("git_commit") == metadata.get("github_sha")
            checks["metadata_says_historical_vulnerability_not_reproduced"] = metadata.get("historical_vulnerability_reproduced") is False

            failed = sorted(key for key, passed in checks.items() if passed is not True)
            return {
                "schema_version": 1,
                "integrity_verified": not failed,
                "authenticity": "UNTRUSTED_UNSIGNED",
                "github_attestation": "NOT_CHECKED_OFFLINE",
                "archive_sha256": _sha256(archive_path),
                "archive_size_bytes": archive_path.stat().st_size,
                "probe_artifact_integrity_verified": True,
                "checks": checks,
                "failed_checks": failed,
                "historical_vulnerability": "INCONCLUSIVE",
                "historical_source_to_binary_provenance": "NOT_ESTABLISHED",
                "note": "This verifies archive integrity and cross-run consistency only. Verify GitHub provenance separately with gh attestation verify.",
            }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="path to evm-key-forensics-complete-evidence.zip")
    args = parser.parse_args(argv)
    try:
        result = verify_complete_archive(args.archive)
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as exc:
        result = {
            "integrity_verified": False,
            "authenticity": "UNTRUSTED_UNSIGNED",
            "github_attestation": "NOT_CHECKED_OFFLINE",
            "error": str(exc),
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("integrity_verified") else 1


if __name__ == "__main__":
    raise SystemExit(main())
