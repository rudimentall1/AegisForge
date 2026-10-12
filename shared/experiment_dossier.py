"""Strict, unsigned experiment dossier validation for the EVM Key Forensics lab.

A valid dossier is structured input, not proof of execution or issuer identity.
"""

import hashlib
import json
import re
from datetime import datetime

SCHEMA_VERSION = "evm-key-forensics-experiment-dossier-v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40,64}$")
_TOP_FIELDS = {
    "schema_version", "experiment_id", "run_id", "nonce", "source", "fixture",
    "command", "harness", "runner", "execution", "result_sha256", "artifacts", "safety",
}


class ExperimentDossierError(ValueError):
    """Raised when a dossier is incomplete, ambiguous, or malformed."""


def _object(value, field, expected):
    if not isinstance(value, dict):
        raise ExperimentDossierError(f"{field}_must_be_object")
    if set(value) != expected:
        missing = sorted(expected - set(value))
        extra = sorted(set(value) - expected)
        if missing:
            raise ExperimentDossierError(f"{field}_fields_missing:" + ",".join(missing))
        raise ExperimentDossierError(f"{field}_fields_unknown:" + ",".join(extra))
    return value


def _text(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ExperimentDossierError(f"{field}_required")
    if value != value.strip():
        raise ExperimentDossierError(f"{field}_surrounding_whitespace")
    return value


def _digest(value, field):
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ExperimentDossierError(f"{field}_invalid_sha256")
    return value


def _timestamp(value, field):
    _text(value, field)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("timezone required")
        return parsed
    except (ValueError, TypeError, OverflowError) as exc:
        raise ExperimentDossierError(f"{field}_invalid_timestamp") from exc


def validate_experiment_dossier(dossier):
    """Validate the exact dossier schema and return a safe summary.

    This deliberately does not qualify a reproduction, verify an attestation,
    inspect artifact bytes, or establish runner independence.
    """
    _object(dossier, "dossier", _TOP_FIELDS)
    if dossier["schema_version"] != SCHEMA_VERSION:
        raise ExperimentDossierError("unsupported_dossier_schema")
    for field in ("experiment_id", "run_id", "nonce"):
        _text(dossier[field], field)

    source = _object(dossier["source"], "source", {"repository", "revision"})
    _text(source["repository"], "source_repository")
    if not isinstance(source["revision"], str) or not _REVISION.fullmatch(source["revision"]):
        raise ExperimentDossierError("source_revision_must_be_full_git_object_id")

    fixture = _object(dossier["fixture"], "fixture", {"fixture_id", "sha256"})
    _text(fixture["fixture_id"], "fixture_id")
    _digest(fixture["sha256"], "fixture_sha256")

    command = _object(dossier["command"], "command", {"argv", "argv_sha256"})
    argv = command["argv"]
    if not isinstance(argv, list) or not argv or not all(isinstance(arg, str) for arg in argv):
        raise ExperimentDossierError("command_argv_must_be_nonempty_string_list")
    expected_argv_digest = hashlib.sha256(canonical_json(argv).encode("utf-8")).hexdigest()
    if _digest(command["argv_sha256"], "command_argv_sha256") != expected_argv_digest:
        raise ExperimentDossierError("command_argv_digest_mismatch")

    harness = _object(dossier["harness"], "harness", {"harness_sha256", "build_recipe_sha256"})
    _digest(harness["harness_sha256"], "harness_sha256")
    _digest(harness["build_recipe_sha256"], "build_recipe_sha256")

    runner = _object(dossier["runner"], "runner", {"provider_id", "runner_id", "image_digest"})
    for field in ("provider_id", "runner_id"):
        _text(runner[field], field)
    image_digest = runner["image_digest"]
    if image_digest is not None:
        _digest(image_digest, "runner_image_digest")

    execution = _object(dossier["execution"], "execution", {
        "started_at", "completed_at", "exit_code", "timed_out", "test_passed",
    })
    started = _timestamp(execution["started_at"], "execution_started_at")
    completed = _timestamp(execution["completed_at"], "execution_completed_at")
    if completed < started:
        raise ExperimentDossierError("execution_time_order_invalid")
    if isinstance(execution["exit_code"], bool) or not isinstance(execution["exit_code"], int):
        raise ExperimentDossierError("execution_exit_code_must_be_integer")
    for field in ("timed_out", "test_passed"):
        if not isinstance(execution[field], bool):
            raise ExperimentDossierError(f"execution_{field}_must_be_boolean")
    _digest(dossier["result_sha256"], "result_sha256")

    artifacts = dossier["artifacts"]
    if not isinstance(artifacts, list):
        raise ExperimentDossierError("artifacts_must_be_list")
    seen_names = set()
    for index, artifact in enumerate(artifacts):
        artifact = _object(artifact, f"artifact_{index}", {"name", "sha256"})
        name = _text(artifact["name"], f"artifact_{index}_name")
        # Artifact names are portable POSIX-relative paths, independent of the
        # platform performing verification. Reject normalization ambiguities
        # before pathlib can silently collapse "." or repeated separators.
        if (
            "\\" in name
            or "\x00" in name
            or name.startswith("/")
            or re.match(r"^[A-Za-z]:", name)
            or any(part in ("", ".", "..") for part in name.split("/"))
        ):
            raise ExperimentDossierError("artifact_path_invalid")
        if name in seen_names:
            raise ExperimentDossierError("duplicate_artifact_name")
        seen_names.add(name)
        _digest(artifact["sha256"], f"artifact_{index}_sha256")

    safety = _object(dossier["safety"], "safety", {
        "scope", "historical_code_executed", "real_key_material_handled",
    })
    if not isinstance(safety["scope"], str) or safety["scope"] not in {"synthetic_only", "source_inspection_only"}:
        raise ExperimentDossierError("unsafe_or_unknown_experiment_scope")
    for field in ("historical_code_executed", "real_key_material_handled"):
        if not isinstance(safety[field], bool):
            raise ExperimentDossierError(f"safety_{field}_must_be_boolean")
    if safety["scope"] == "source_inspection_only" and safety["historical_code_executed"]:
        raise ExperimentDossierError("source_inspection_scope_conflicts_with_execution_claim")
    if safety["scope"] == "synthetic_only" and safety["real_key_material_handled"]:
        raise ExperimentDossierError("synthetic_scope_conflicts_with_key_material_claim")

    return {
        "valid": True,
        "schema_version": SCHEMA_VERSION,
        "experiment_id": dossier["experiment_id"],
        "run_id": dossier["run_id"],
        "artifact_count": len(artifacts),
        "dossier_sha256": dossier_sha256(dossier),
        "qualification": "NOT_ESTABLISHED",
    }


def _validate_json_value(value):
    """Reject Python values that do not have an unambiguous JSON representation."""
    if value is None or type(value) in (bool, int):
        return
    if type(value) is str:
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise ExperimentDossierError("dossier_not_canonicalizable") from exc
        return
    if type(value) is float:
        import math
        if not math.isfinite(value):
            raise ExperimentDossierError("dossier_not_canonicalizable")
        return
    if type(value) is list:
        for item in value:
            _validate_json_value(item)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise ExperimentDossierError("dossier_json_object_keys_must_be_strings")
            _validate_json_value(key)
            _validate_json_value(item)
        return
    raise ExperimentDossierError("dossier_not_canonicalizable")


def canonical_json(value):
    """Serialize strict JSON values deterministically for local digests."""
    _validate_json_value(value)
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ExperimentDossierError("dossier_not_canonicalizable") from exc


def dossier_sha256(dossier):
    """Hash canonical dossier bytes; the digest is integrity metadata, not a signature."""
    return hashlib.sha256(canonical_json(dossier).encode("utf-8")).hexdigest()


def verify_experiment_dossier_artifacts(dossier, artifact_root):
    """Verify artifact bytes through file descriptors anchored to a local root.

    Directory-relative opens and O_NOFOLLOW prevent a path component from being
    swapped for a symlink between validation and opening. This binds bytes to
    declared digests only; it does not establish provenance or execution.
    """
    import errno
    import os
    import stat
    from pathlib import Path

    validate_experiment_dossier(dossier)
    root = Path(artifact_root).resolve(strict=True)
    if not root.is_dir():
        raise ExperimentDossierError("artifact_root_must_be_directory")

    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None or not hasattr(os, "supports_dir_fd") or os.open not in os.supports_dir_fd:
        raise ExperimentDossierError("secure_artifact_open_unsupported")

    verified = []
    root_fd = None
    try:
        root_fd = os.open(str(root), os.O_RDONLY | directory | nofollow)
        for artifact in dossier["artifacts"]:
            name = artifact["name"]
            relative = Path(name)
            if relative.is_absolute() or not relative.parts or any(part in ("", ".", "..") for part in relative.parts):
                raise ExperimentDossierError("artifact_path_invalid")

            parent_fd = os.dup(root_fd)
            file_fd = None
            try:
                # Walk each directory from the already-open root. A concurrent
                # rename cannot redirect this descriptor into another tree.
                for part in relative.parts[:-1]:
                    next_fd = os.open(
                        part, os.O_RDONLY | directory | nofollow, dir_fd=parent_fd
                    )
                    os.close(parent_fd)
                    parent_fd = next_fd

                try:
                    file_fd = os.open(
                        relative.parts[-1], os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0),
                        dir_fd=parent_fd,
                    )
                except OSError as exc:
                    if exc.errno == errno.ELOOP:
                        raise ExperimentDossierError("artifact_symlink_not_allowed") from exc
                    raise

                metadata_before = os.fstat(file_fd)
                if not stat.S_ISREG(metadata_before.st_mode):
                    raise ExperimentDossierError("artifact_not_regular_file")

                digest_builder = hashlib.sha256()
                bytes_read = 0
                while True:
                    chunk = os.read(file_fd, 1024 * 1024)
                    if not chunk:
                        break
                    bytes_read += len(chunk)
                    digest_builder.update(chunk)
                metadata_after = os.fstat(file_fd)
                stable_fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
                if (
                    any(getattr(metadata_before, field, None) != getattr(metadata_after, field, None)
                        for field in stable_fields)
                    or bytes_read != metadata_after.st_size
                ):
                    raise ExperimentDossierError("artifact_changed_during_verification")
                digest = digest_builder.hexdigest()
            except ExperimentDossierError:
                raise
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise ExperimentDossierError("artifact_symlink_not_allowed") from exc
                raise ExperimentDossierError("artifact_path_unavailable_or_escaped") from exc
            finally:
                if file_fd is not None:
                    os.close(file_fd)
                os.close(parent_fd)

            if digest != artifact["sha256"]:
                raise ExperimentDossierError("artifact_bytes_digest_mismatch")
            verified.append({"name": name, "sha256": digest})
    except ExperimentDossierError:
        raise
    except OSError as exc:
        raise ExperimentDossierError("artifact_root_or_path_unavailable") from exc
    finally:
        if root_fd is not None:
            os.close(root_fd)

    return {
        "verified": True,
        "artifact_count": len(verified),
        "artifacts": verified,
        "qualification": "NOT_ESTABLISHED",
    }
