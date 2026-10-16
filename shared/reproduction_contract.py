"""Versioned, non-executing contract for reproducible security experiments.

This module validates the declaration of a bounded experiment. It never executes
commands, enables networking, loads secrets, or interprets a contract as a finding.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

REPRODUCTION_CONTRACT_VERSION = "aegisforge-reproduction-contract-v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
_SENSITIVE_ENV_RE = re.compile(
    r"(?:SECRET|TOKEN|PASSWORD|PRIVATE_KEY|SEED|MNEMONIC|CREDENTIAL|AUTHORIZATION|ACCESS_KEY)",
    re.IGNORECASE,
)
_MAX_COMMAND_ARGS = 128
_MAX_OUTPUTS = 128
_MAX_TEXT_BYTES = 4096


class ReproductionContractError(ValueError):
    """A reproduction contract is malformed, unsafe, or incomplete."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReproductionContractError(f"duplicate_json_key:{key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ReproductionContractError(f"nonstandard_json_constant:{value}")


def _text(value: object, field: str, *, max_bytes: int = _MAX_TEXT_BYTES) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > max_bytes:
        raise ReproductionContractError(f"{field}_invalid")
    if "\x00" in value:
        raise ReproductionContractError(f"{field}_contains_nul")
    return value.strip()


def _safe_relative_path(value: object, field: str, *, allow_root: bool = False) -> str:
    path = _text(value, field)
    if allow_root and path == ".":
        return path
    if path.startswith("/") or "\\" in path:
        raise ReproductionContractError(f"{field}_invalid")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ReproductionContractError(f"{field}_invalid")
    if parts and ":" in parts[0]:
        raise ReproductionContractError(f"{field}_invalid")
    return path


def _bounded_int(value: object, field: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ReproductionContractError(f"{field}_out_of_bounds")
    return value


def _object(value: object, field: str, expected_fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReproductionContractError(f"{field}_must_be_object")
    if set(value) != expected_fields:
        raise ReproductionContractError(f"{field}_fields_invalid")
    return value


def validate_reproduction_contract(payload: object) -> dict[str, Any]:
    """Validate a versioned, network-disabled, resource-bounded reproduction declaration."""
    top = _object(payload, "contract", {
        "schema_version", "contract_id", "case_id", "hypothesis_id", "target",
        "toolchain", "command", "working_directory", "environment",
        "network_access", "limits", "expected_exit_code", "expected_outputs",
    })
    if top["schema_version"] != REPRODUCTION_CONTRACT_VERSION:
        raise ReproductionContractError("schema_version_unsupported")

    contract_id = _text(top["contract_id"], "contract_id")
    case_id = _text(top["case_id"], "case_id")
    hypothesis_id = _text(top["hypothesis_id"], "hypothesis_id")

    target = _object(top["target"], "target", {
        "repository", "commit_sha", "scope_reference", "source_path",
    })
    repository = _text(target["repository"], "target_repository", max_bytes=256)
    if not _REPOSITORY_RE.fullmatch(repository):
        raise ReproductionContractError("target_repository_invalid")
    commit_sha = _text(target["commit_sha"], "target_commit_sha", max_bytes=40)
    if not _COMMIT_RE.fullmatch(commit_sha):
        raise ReproductionContractError("target_commit_sha_invalid")
    scope_reference = _text(target["scope_reference"], "scope_reference", max_bytes=2048)
    if not scope_reference.startswith("https://"):
        raise ReproductionContractError("scope_reference_must_be_https")
    source_path = _safe_relative_path(target["source_path"], "target_source_path")

    toolchain = _object(top["toolchain"], "toolchain", {
        "runtime", "version", "image_digest",
    })
    runtime = _text(toolchain["runtime"], "toolchain_runtime", max_bytes=128)
    runtime_version = _text(toolchain["version"], "toolchain_version", max_bytes=128)
    image_digest = _text(toolchain["image_digest"], "toolchain_image_digest", max_bytes=71)
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest):
        raise ReproductionContractError("toolchain_image_digest_invalid")

    command = top["command"]
    if not isinstance(command, list) or not command or len(command) > _MAX_COMMAND_ARGS:
        raise ReproductionContractError("command_must_be_bounded_argv")
    normalized_command = []
    for index, arg in enumerate(command):
        normalized_command.append(_text(arg, f"command_arg_{index}", max_bytes=_MAX_TEXT_BYTES))

    working_directory = _safe_relative_path(
        top["working_directory"], "working_directory", allow_root=True
    )

    environment = top["environment"]
    if not isinstance(environment, dict) or len(environment) > 128:
        raise ReproductionContractError("environment_must_be_bounded_object")
    normalized_environment: dict[str, str] = {}
    for key, value in environment.items():
        if not isinstance(key, str) or not _ENV_NAME_RE.fullmatch(key):
            raise ReproductionContractError("environment_name_invalid")
        if _SENSITIVE_ENV_RE.search(key):
            raise ReproductionContractError(f"environment_secret_name_rejected:{key}")
        text_value = _text(value, f"environment_value_{key}")
        if "\n" in text_value or "\r" in text_value:
            raise ReproductionContractError(f"environment_value_multiline:{key}")
        normalized_environment[key] = text_value

    if top["network_access"] != "disabled":
        raise ReproductionContractError("network_access_must_be_disabled")

    limits = _object(top["limits"], "limits", {
        "timeout_seconds", "cpu_cores", "memory_mb", "max_processes", "max_output_bytes",
    })
    normalized_limits = {
        "timeout_seconds": _bounded_int(limits["timeout_seconds"], "timeout_seconds", 1, 3600),
        "cpu_cores": _bounded_int(limits["cpu_cores"], "cpu_cores", 1, 8),
        "memory_mb": _bounded_int(limits["memory_mb"], "memory_mb", 64, 16384),
        "max_processes": _bounded_int(limits["max_processes"], "max_processes", 1, 256),
        "max_output_bytes": _bounded_int(
            limits["max_output_bytes"], "max_output_bytes", 1, 64 * 1024 * 1024
        ),
    }
    expected_exit_code = _bounded_int(top["expected_exit_code"], "expected_exit_code", 0, 255)

    expected_outputs = top["expected_outputs"]
    if not isinstance(expected_outputs, list) or not expected_outputs or len(expected_outputs) > _MAX_OUTPUTS:
        raise ReproductionContractError("expected_outputs_must_be_bounded_list")
    normalized_outputs = []
    seen_paths: set[str] = set()
    for item in expected_outputs:
        output = _object(item, "expected_output", {"path", "sha256"})
        output_path = _safe_relative_path(output["path"], "expected_output_path")
        if output_path in seen_paths:
            raise ReproductionContractError("expected_output_path_duplicate")
        seen_paths.add(output_path)
        digest = _text(output["sha256"], "expected_output_sha256", max_bytes=64)
        if not _SHA256_RE.fullmatch(digest):
            raise ReproductionContractError("expected_output_sha256_invalid")
        normalized_outputs.append({"path": output_path, "sha256": digest})

    normalized_outputs.sort(key=lambda item: item["path"])
    return {
        "schema_version": REPRODUCTION_CONTRACT_VERSION,
        "contract_id": contract_id,
        "case_id": case_id,
        "hypothesis_id": hypothesis_id,
        "target": {
            "repository": repository,
            "commit_sha": commit_sha,
            "scope_reference": scope_reference,
            "source_path": source_path,
        },
        "toolchain": {
            "runtime": runtime,
            "version": runtime_version,
            "image_digest": image_digest,
        },
        "command": normalized_command,
        "working_directory": working_directory,
        "environment": dict(sorted(normalized_environment.items())),
        "network_access": "disabled",
        "limits": normalized_limits,
        "expected_exit_code": expected_exit_code,
        "expected_outputs": normalized_outputs,
    }


def load_reproduction_contract(raw: bytes | str) -> dict[str, Any]:
    """Strictly parse JSON and validate it; duplicate keys and nonstandard numbers fail."""
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ReproductionContractError("contract_invalid_utf8") from exc
    elif isinstance(raw, str):
        text = raw
    else:
        raise ReproductionContractError("contract_input_must_be_bytes_or_text")
    try:
        payload = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ReproductionContractError("contract_invalid_json") from exc
    return validate_reproduction_contract(payload)


def canonical_contract_bytes(payload: object) -> bytes:
    """Return deterministic JSON bytes for a valid contract."""
    normalized = validate_reproduction_contract(payload)
    return json.dumps(
        normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def contract_sha256(payload: object) -> str:
    """Hash a validated canonical contract; this is integrity metadata, not authenticity."""
    return hashlib.sha256(canonical_contract_bytes(payload)).hexdigest()
