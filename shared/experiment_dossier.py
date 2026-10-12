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
