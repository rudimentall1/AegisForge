"""Bounded offline solc compilation for an acquired on-chain source snapshot."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any

from agents.security_checker.foundry_runner import _resolve_solc_binary
from shared.sandbox import SandboxError, SandboxLimits, run_in_container
from shared.solidity_bytecode_verifier import (
    CompilerRuntimeVerification,
    verify_compiler_runtime_match,
)


_MAX_INPUT_BYTES = 8 * 1024 * 1024
_MAX_COMPILER_BYTES = 128 * 1024 * 1024
_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
_MAX_TIMEOUT_SECONDS = 180
_IMAGE_RE = re.compile(r"ghcr\.io/foundry-rs/foundry@sha256:[0-9a-f]{64}")
_VERSION_RE = re.compile(r"^v?(\d+\.\d+\.\d+)(?:\+commit\.([0-9a-fA-F]+))?$")
_ACTUAL_VERSION_RE = re.compile(r"Version:\s*(\d+\.\d+\.\d+(?:\+commit\.[0-9a-fA-F]+)?)")


@dataclass(frozen=True, slots=True)
class SolidityCompilation:
    status: str
    reason: str
    compiler_output: dict[str, Any] | None = None
    compiler_version: str = ""
    input_sha256: str = ""
    compiler_binary_sha256: str = ""
    isolation: str = ""


def _result(status: str, reason: str, **kwargs) -> SolidityCompilation:
    return SolidityCompilation(status=status, reason=reason, **kwargs)


def _version_parts(value: object):
    if not isinstance(value, str):
        return None
    match = _VERSION_RE.fullmatch(value.strip())
    if match is None:
        return None
    return match.group(1), match.group(2).lower() if match.group(2) else None


def _read_compiler_version(binary: Path) -> str | None:
    try:
        completed = subprocess.run(
            [str(binary), "--version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = (completed.stdout or "") + (completed.stderr or "")
    match = _ACTUAL_VERSION_RE.search(output)
    if completed.returncode != 0 or match is None:
        return None
    return match.group(1)


def _requests_deployed_bytecode(standard_input: dict[str, Any]) -> bool:
    selection = standard_input.get("settings", {}).get("outputSelection")
    if not isinstance(selection, dict):
        return False
    accepted = {
        "evm.deployedBytecode",
        "evm.deployedBytecode.object",
        "evm.deployedBytecode.*",
        "*",
    }
    for contract_map in selection.values():
        if not isinstance(contract_map, dict):
            continue
        for outputs in contract_map.values():
            if isinstance(outputs, list) and any(item in accepted for item in outputs):
                return True
    return False


def compile_standard_json(
    standard_json_input: str | None,
    compiler_version: str | None,
    *,
    image: str | None = None,
    timeout_seconds: int = 90,
) -> SolidityCompilation:
    """Compile exact preserved Standard JSON input in a networkless container."""
    if not isinstance(standard_json_input, str) or not standard_json_input:
        return _result("INCOMPLETE", "standard_json_input_missing")
    input_bytes = standard_json_input.encode("utf-8")
    if len(input_bytes) > _MAX_INPUT_BYTES:
        return _result("INPUT_TOO_LARGE", "standard_json_input_too_large")
    try:
        standard_input = json.loads(standard_json_input)
    except json.JSONDecodeError:
        return _result("INCOMPLETE", "standard_json_input_invalid")
    if (
        not isinstance(standard_input, dict)
        or standard_input.get("language") != "Solidity"
        or not isinstance(standard_input.get("sources"), dict)
        or not standard_input["sources"]
        or not isinstance(standard_input.get("settings"), dict)
    ):
        return _result("INCOMPLETE", "standard_json_input_incomplete")
    if not _requests_deployed_bytecode(standard_input):
        return _result("INCOMPLETE", "deployed_bytecode_output_not_requested")
    expected = _version_parts(compiler_version)
    if expected is None:
        return _result("INCOMPLETE", "compiler_version_metadata_missing")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= _MAX_TIMEOUT_SECONDS:
        return _result("INVALID_INPUT", "timeout_invalid")

    configured_image = image if image is not None else os.getenv("AEGISFORGE_FOUNDRY_IMAGE", "").strip()
    if not isinstance(configured_image, str) or not _IMAGE_RE.fullmatch(configured_image):
        return _result("RUNNER_NOT_CONFIGURED", "digest_pinned_foundry_image_required")

    compiler = _resolve_solc_binary(expected[0])
    if compiler is None:
        return _result("COMPILER_UNAVAILABLE", "required_solc_binary_not_installed")
    try:
        compiler_bytes = compiler.read_bytes()
    except OSError:
        return _result("COMPILER_UNAVAILABLE", "required_solc_binary_unreadable")
    if not compiler_bytes or len(compiler_bytes) > _MAX_COMPILER_BYTES:
        return _result("COMPILER_UNAVAILABLE", "required_solc_binary_size_invalid")
    compiler_digest = hashlib.sha256(compiler_bytes).hexdigest()
    input_digest = hashlib.sha256(input_bytes).hexdigest()
    try:
        with tempfile.TemporaryDirectory(prefix="aegisforge-solc-") as temporary:
            root = Path(temporary)
            compiler_dir = root / ".aegisforge"
            compiler_dir.mkdir()
            compiler_copy = compiler_dir / "solc"
            compiler_copy.write_bytes(compiler_bytes)
            compiler_copy.chmod(0o555)
            actual_version = _read_compiler_version(compiler_copy)
            actual = _version_parts(actual_version)
            if actual is None:
                return _result(
                    "COMPILER_UNAVAILABLE",
                    "required_solc_binary_probe_failed",
                    input_sha256=input_digest,
                    compiler_binary_sha256=compiler_digest,
                )
            if actual[0] != expected[0] or (expected[1] is not None and expected[1] != actual[1]):
                return _result(
                    "COMPILER_VERSION_MISMATCH",
                    "required_solc_binary_version_mismatch",
                    compiler_version=actual_version,
                    input_sha256=input_digest,
                    compiler_binary_sha256=compiler_digest,
                )
            input_path = root / "standard-input.json"
            input_path.write_bytes(input_bytes)
            input_path.chmod(0o444)
            root.chmod(0o755)
            observation = run_in_container(
                ["--standard-json"],
                SandboxLimits(
                    timeout_seconds=timeout_seconds,
                    memory_mb=2048,
                    cpu_cores=2,
                    max_output_bytes=_MAX_OUTPUT_BYTES,
                    network="none",
                ),
                root,
                image=configured_image,
                entrypoint="/work/.aegisforge/solc",
                stdin_path=input_path,
            )
    except SandboxError as exc:
        reason = str(exc)
        status = "TIMEOUT" if reason == "execution_timeout" else "RUNNER_UNAVAILABLE"
        return _result(
            status,
            reason,
            compiler_version=actual_version or "",
            input_sha256=input_digest,
            compiler_binary_sha256=compiler_digest,
        )
    except OSError:
        return _result(
            "EXECUTION_FAILED",
            "compiler_workspace_io_failed",
            compiler_version=actual_version or "",
            input_sha256=input_digest,
            compiler_binary_sha256=compiler_digest,
        )

    if observation.stdout_truncated or observation.stderr_truncated:
        return _result(
            "OUTPUT_TRUNCATED",
            "compiler_output_truncated",
            compiler_version=actual_version,
            input_sha256=input_digest,
            compiler_binary_sha256=compiler_digest,
            isolation=observation.isolation,
        )
    try:
        compiler_output = json.loads(observation.stdout)
    except (TypeError, json.JSONDecodeError):
        return _result(
            "INVALID_OUTPUT",
            "compiler_json_output_invalid",
            compiler_version=actual_version,
            input_sha256=input_digest,
            compiler_binary_sha256=compiler_digest,
            isolation=observation.isolation,
        )
    if not isinstance(compiler_output, dict):
        return _result("INVALID_OUTPUT", "compiler_json_output_invalid")
    errors = compiler_output.get("errors", [])
    if not isinstance(errors, list):
        return _result("INVALID_OUTPUT", "compiler_errors_invalid")
    if observation.exit_code != 0 or any(
        isinstance(item, dict) and item.get("severity") == "error"
        for item in errors
    ):
        return _result(
            "COMPILER_ERROR",
            "solc_reported_compilation_error",
            compiler_output=compiler_output,
            compiler_version=actual_version,
            input_sha256=input_digest,
            compiler_binary_sha256=compiler_digest,
            isolation=observation.isolation,
        )
    return _result(
        "COMPILED",
        "standard_json_compilation_succeeded",
        compiler_output=compiler_output,
        compiler_version=actual_version,
        input_sha256=input_digest,
        compiler_binary_sha256=compiler_digest,
        isolation=observation.isolation,
    )


def verify_onchain_target(
    target: Any,
    contract_file: str,
    *,
    image: str | None = None,
) -> CompilerRuntimeVerification:
    """Compile and compare one immutable target record; never execute target code."""
    compilation = compile_standard_json(
        getattr(target, "standard_json_input", None),
        getattr(target, "compiler_version", None),
        image=image,
    )
    if compilation.status != "COMPILED":
        return CompilerRuntimeVerification(
            "INCOMPLETE",
            "compiler_" + compilation.status.lower() + ":" + compilation.reason,
        )
    return verify_compiler_runtime_match(
        standard_json_input=target.standard_json_input,
        source_files=dict(target.source_files),
        compiled_input_sha256=compilation.input_sha256,
        compiler_output=compilation.compiler_output,
        deployed_runtime_code=getattr(target, "runtime_code", ""),
        expected_compiler_version=target.compiler_version,
        actual_compiler_version=compilation.compiler_version,
        contract_file=contract_file,
        contract_name=target.contract_name,
        proxy_type=target.proxy_type,
        implementations=target.implementations,
    )
