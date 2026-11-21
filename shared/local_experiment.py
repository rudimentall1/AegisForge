"""Canonical, non-executing records for deterministic local experiments.

This module packages raw process outputs and execution metadata after a caller has
run an experiment in an approved environment. It deliberately never executes
commands, resolves paths, or treats a passing exit code as proof of a vulnerability.
"""
from __future__ import annotations

import hashlib
import re
from typing import Mapping

LEGACY_SCHEMA_VERSION = "aegisforge-local-experiment-v1"
SCHEMA_VERSION = "aegisforge-local-experiment-v2"
_ARTIFACT_NAMES = ("input.bin", "stdout.bin", "stderr.bin")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
_MAX_TOTAL_BYTES = 20 * 1024 * 1024
_MAX_ARG_COUNT = 128
_MAX_TOOLCHAIN_ITEMS = 64
_MAX_TEXT_BYTES = 16 * 1024


class ExperimentRecordError(ValueError):
    """Raised when experiment metadata or raw artifacts are invalid."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ExperimentRecordError(f"{field}_required")
    if len(value.encode("utf-8")) > _MAX_TEXT_BYTES:
        raise ExperimentRecordError(f"{field}_too_large")
    return value


def build_experiment_record(
    *,
    case_id: str,
    round_id: str,
    task_id: str,
    target_repository: str,
    target_commit: str,
    argv: list[str],
    toolchain: Mapping[str, str],
    input_bytes: bytes,
    stdout_bytes: bytes,
    stderr_bytes: bytes,
    exit_code: int | None,
    expected_exit_code: int = 0,
    round_spec_id: str | None = None,
) -> tuple[dict, dict[str, bytes]]:
    """Build a canonical metadata record and its raw, bounded artifacts.

    argv is descriptive metadata only: this function does not execute it. Callers
    must not pass secrets in argv or toolchain values because the record is portable.
    """
    for field, value in (
        ("case_id", case_id),
        ("round_id", round_id),
        ("task_id", task_id),
    ):
        _require_text(value, field)
    if round_spec_id is not None:
        round_spec_id = _require_text(round_spec_id, "round_spec_id")
    if (not isinstance(target_repository, str)
            or len(target_repository.encode("utf-8")) > _MAX_TEXT_BYTES
            or not _REPOSITORY_RE.fullmatch(target_repository)):
        raise ExperimentRecordError("target_repository_must_be_owner_repo")
    if not isinstance(target_commit, str) or not _COMMIT_RE.fullmatch(target_commit):
        raise ExperimentRecordError("target_commit_must_be_full_git_sha")
    if not isinstance(argv, list) or not argv or len(argv) > _MAX_ARG_COUNT:
        raise ExperimentRecordError("argv_invalid")
    if any(not isinstance(arg, str) or len(arg.encode("utf-8")) > _MAX_TEXT_BYTES for arg in argv):
        raise ExperimentRecordError("argv_item_invalid")
    if (not isinstance(toolchain, Mapping) or not toolchain
            or len(toolchain) > _MAX_TOOLCHAIN_ITEMS):
        raise ExperimentRecordError("toolchain_required")
    normalized_toolchain = {}
    for key, value in toolchain.items():
        normalized_toolchain[_require_text(key, "toolchain_key")] = _require_text(
            value, "toolchain_value"
        )
    if exit_code is not None and type(exit_code) is not int:
        raise ExperimentRecordError("exit_code_invalid")
    if type(expected_exit_code) is not int:
        raise ExperimentRecordError("expected_exit_code_invalid")

    artifacts = {
        "input.bin": input_bytes,
        "stdout.bin": stdout_bytes,
        "stderr.bin": stderr_bytes,
    }
    if any(not isinstance(value, bytes) for value in artifacts.values()):
        raise ExperimentRecordError("artifact_bytes_required")
    total_size = 0
    manifest = {}
    for name in _ARTIFACT_NAMES:
        data = artifacts[name]
        if len(data) > _MAX_ARTIFACT_BYTES:
            raise ExperimentRecordError(f"artifact_size_limit_exceeded:{name}")
        total_size += len(data)
        manifest[name] = {"size_bytes": len(data), "sha256": _sha256(data)}
    if total_size > _MAX_TOTAL_BYTES:
        raise ExperimentRecordError("experiment_artifact_total_size_limit_exceeded")

    status = "NOT_RUN" if exit_code is None else (
        "PASS" if exit_code == expected_exit_code else "FAIL"
    )
    record = {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "round_id": round_id,
        "round_spec_id": round_spec_id,
        "task_id": task_id,
        "target_repository": target_repository,
        "target_commit": target_commit,
        "argv": list(argv),
        "toolchain": dict(sorted(normalized_toolchain.items())),
        "exit_code": exit_code,
        "expected_exit_code": expected_exit_code,
        "status": status,
        "artifacts": manifest,
    }
    return record, artifacts


def verify_experiment_record(
    record: object, artifacts: Mapping[str, bytes]
) -> dict:
    """Verify record shape, outcome semantics, exact artifact set, sizes and hashes."""
    if not isinstance(record, dict):
        return {"status": "FAIL", "errors": ["record_must_be_object"]}
    legacy_required = {
        "schema_version", "case_id", "round_id", "task_id", "target_repository", "target_commit",
        "argv", "toolchain", "exit_code", "expected_exit_code", "status", "artifacts",
    }
    schema_version = record.get("schema_version")
    if schema_version == LEGACY_SCHEMA_VERSION:
        required = legacy_required
    elif schema_version == SCHEMA_VERSION:
        required = legacy_required | {"round_spec_id"}
    else:
        return {"status": "FAIL", "errors": ["schema_version_unsupported"]}
    if set(record) != required:
        return {"status": "FAIL", "errors": ["record_schema_invalid"]}
    round_spec_id = record.get("round_spec_id")
    if round_spec_id is not None and (
        not isinstance(round_spec_id, str)
        or not round_spec_id.strip()
        or len(round_spec_id.encode("utf-8")) > _MAX_TEXT_BYTES
    ):
        return {"status": "FAIL", "errors": ["round_spec_id_invalid"]}
    for field in ("case_id", "round_id", "task_id"):
        value = record.get(field)
        if (not isinstance(value, str) or not value.strip()
                or len(value.encode("utf-8")) > _MAX_TEXT_BYTES):
            return {"status": "FAIL", "errors": [f"{field}_invalid"]}
    target_repository = record.get("target_repository")
    if (not isinstance(target_repository, str)
            or len(target_repository.encode("utf-8")) > _MAX_TEXT_BYTES
            or not _REPOSITORY_RE.fullmatch(target_repository)):
        return {"status": "FAIL", "errors": ["target_repository_invalid"]}
    target_commit = record.get("target_commit")
    if not isinstance(target_commit, str) or not _COMMIT_RE.fullmatch(target_commit):
        return {"status": "FAIL", "errors": ["target_commit_invalid"]}
    argv = record.get("argv")
    toolchain = record.get("toolchain")
    if (not isinstance(argv, list) or not argv or len(argv) > _MAX_ARG_COUNT
            or any(not isinstance(item, str) or len(item.encode("utf-8")) > _MAX_TEXT_BYTES
                   for item in argv)):
        return {"status": "FAIL", "errors": ["argv_invalid"]}
    if (not isinstance(toolchain, dict) or not toolchain
            or len(toolchain) > _MAX_TOOLCHAIN_ITEMS
            or any(not isinstance(k, str) or not k.strip()
                   or len(k.encode("utf-8")) > _MAX_TEXT_BYTES
                   or not isinstance(v, str) or not v.strip()
                   or len(v.encode("utf-8")) > _MAX_TEXT_BYTES
                   for k, v in toolchain.items())):
        return {"status": "FAIL", "errors": ["toolchain_invalid"]}
    exit_code = record.get("exit_code")
    expected = record.get("expected_exit_code")
    if (exit_code is not None and type(exit_code) is not int) or type(expected) is not int:
        return {"status": "FAIL", "errors": ["exit_code_invalid"]}
    expected_status = "NOT_RUN" if exit_code is None else (
        "PASS" if exit_code == expected else "FAIL"
    )
    if record.get("status") != expected_status:
        return {"status": "FAIL", "errors": ["outcome_status_inconsistent"]}

    manifest = record.get("artifacts")
    if not isinstance(manifest, dict) or set(manifest) != set(_ARTIFACT_NAMES):
        return {"status": "FAIL", "errors": ["artifact_manifest_invalid"]}
    if not isinstance(artifacts, Mapping) or set(artifacts) != set(_ARTIFACT_NAMES):
        return {"status": "FAIL", "errors": ["artifact_set_mismatch"]}

    total_size = 0
    for name in _ARTIFACT_NAMES:
        entry = manifest[name]
        data = artifacts[name]
        if not isinstance(entry, dict) or set(entry) != {"size_bytes", "sha256"}:
            return {"status": "FAIL", "errors": [f"artifact_entry_invalid:{name}"]}
        if not isinstance(data, bytes):
            return {"status": "FAIL", "errors": [f"artifact_bytes_required:{name}"]}
        size = entry.get("size_bytes")
        digest = entry.get("sha256")
        if type(size) is not int or size < 0 or size > _MAX_ARTIFACT_BYTES:
            return {"status": "FAIL", "errors": [f"artifact_size_invalid:{name}"]}
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            return {"status": "FAIL", "errors": [f"artifact_digest_invalid:{name}"]}
        total_size += size
        if total_size > _MAX_TOTAL_BYTES:
            return {"status": "FAIL", "errors": ["experiment_artifact_total_size_limit_exceeded"]}
        if len(data) != size:
            return {"status": "FAIL", "errors": [f"artifact_size_mismatch:{name}"]}
        if _sha256(data) != digest:
            return {"status": "FAIL", "errors": [f"artifact_digest_mismatch:{name}"]}
    return {
        "status": "PASS",
        "experiment_status": expected_status,
        "case_id": record["case_id"],
        "round_id": record["round_id"],
        "round_spec_id": round_spec_id,
        "task_id": record["task_id"],
        "target_repository": target_repository,
        "target_commit": target_commit,
        "checked_artifacts": len(_ARTIFACT_NAMES),
        "errors": [],
    }
