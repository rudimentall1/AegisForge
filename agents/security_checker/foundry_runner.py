from __future__ import annotations

import hashlib
import os
import re
import tempfile
from pathlib import Path, PurePosixPath

from shared.sandbox import SandboxError, SandboxLimits, run_in_container


MAX_SOURCE_FILES = 500
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_TEST_BYTES = 256 * 1024
MAX_OUTPUT_BYTES = 512 * 1024
MAX_TIMEOUT_SECONDS = 300
_TEST_PATH = "test/AegisForgeValidation.t.sol"


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _result(status: str, error: str | None = None) -> dict:
    result = {
        "schema": "aegisforge.foundry_execution.v1",
        "status": status,
        "dynamic_verified": False,
        "confirmed": False,
        "validation_scope": "local_isolated_harness_execution",
        "network_access": False,
        "host_filesystem_access": False,
        "transactions_sent": False,
    }
    if error:
        result["error"] = error
    return result


def _validated_sources(source_files: object) -> tuple[dict[str, str] | None, str | None]:
    if not isinstance(source_files, dict) or not source_files:
        return None, "source_files_invalid"
    if len(source_files) > MAX_SOURCE_FILES:
        return None, "source_file_count_exceeded"

    normalized = {}
    total_bytes = 0
    for name, content in source_files.items():
        if (
            not isinstance(name, str)
            or not name
            or "\\" in name
            or "\x00" in name
            or not isinstance(content, str)
        ):
            return None, "source_path_invalid"
        relative = PurePosixPath(name)
        if (
            relative.is_absolute()
            or not relative.parts
            or any(part in ("", ".", "..") for part in relative.parts)
            or ":" in relative.parts[0]
            or relative.suffix.lower() != ".sol"
        ):
            return None, "source_path_invalid"
        encoded = content.encode("utf-8")
        total_bytes += len(encoded)
        if total_bytes > MAX_SOURCE_BYTES:
            return None, "source_bytes_exceeded"
        normalized[relative.as_posix()] = content
    return normalized, None


def run_foundry_test(
    source_files: dict[str, str],
    test_source: str,
    *,
    compiler_version: str,
    image: str | None = None,
    timeout_seconds: int = 120,
) -> dict:
    """Execute one Solidity harness in a digest-pinned, networkless container.

    This records a bounded local test observation. A passing harness is not,
    by itself, independent proof that a reported vulnerability is exploitable.
    """
    configured_image = (
        image if image is not None
        else os.getenv("AEGISFORGE_FOUNDRY_IMAGE", "").strip()
    )
    if not configured_image:
        return _result("NOT_CONFIGURED", "foundry_container_image_not_configured")
    if not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9./:_-]*@sha256:[0-9a-f]{64}",
        configured_image,
    ):
        return _result("INVALID_CONFIGURATION", "foundry_image_must_be_digest_pinned")
    if (
        not isinstance(compiler_version, str)
        or not re.fullmatch(r"\d+\.\d+\.\d+", compiler_version)
    ):
        return _result("INVALID_INPUT", "compiler_version_invalid")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS
    ):
        return _result("INVALID_INPUT", "timeout_invalid")
    if not isinstance(test_source, str) or not test_source.strip():
        return _result("INVALID_INPUT", "test_source_invalid")
    test_bytes = test_source.encode("utf-8")
    if len(test_bytes) > MAX_TEST_BYTES:
        return _result("INPUT_TOO_LARGE", "test_source_exceeds_size_limit")

    normalized_sources, source_error = _validated_sources(source_files)
    if source_error == "source_bytes_exceeded":
        return _result("INPUT_TOO_LARGE", source_error)
    if source_error:
        return _result("INVALID_INPUT", source_error)

    source_digest = hashlib.sha256()
    for name, content in sorted(normalized_sources.items()):
        source_digest.update(name.encode("utf-8"))
        source_digest.update(b"\x00")
        source_digest.update(content.encode("utf-8"))
        source_digest.update(b"\x00")
    test_digest = _sha256(test_bytes)

    foundry_config = (
        "[profile.default]\n"
        'src = "src"\n'
        'test = "test"\n'
        'out = "/tmp/aegisforge-out"\n'
        'cache_path = "/tmp/aegisforge-cache"\n'
        'libs = ["lib"]\n'
        "ffi = false\n"
        "fs_permissions = []\n"
        "auto_detect_solc = false\n"
        f'solc_version = "{compiler_version}"\n'
    )
    command = [
        "forge",
        "test",
        "--root",
        "/work",
        "--offline",
        "--match-path",
        _TEST_PATH,
        "--json",
        "--out",
        "/tmp/aegisforge-out",
        "--cache-path",
        "/tmp/aegisforge-cache",
    ]

    try:
        with tempfile.TemporaryDirectory(prefix="aegisforge-foundry-") as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "test").mkdir()
            for relative_name, content in normalized_sources.items():
                destination = root / "src" / PurePosixPath(relative_name)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(content, encoding="utf-8")
            (root / _TEST_PATH).write_text(test_source, encoding="utf-8")
            (root / "foundry.toml").write_text(foundry_config, encoding="utf-8")

            observation = run_in_container(
                command,
                SandboxLimits(
                    timeout_seconds=timeout_seconds,
                    memory_mb=2048,
                    cpu_cores=2,
                    max_output_bytes=MAX_OUTPUT_BYTES,
                    network="none",
                ),
                root,
                image=configured_image,
            )
    except SandboxError as exc:
        reason = str(exc)
        if reason == "execution_timeout":
            return _result("TIMEOUT", reason)
        if reason in {"docker_not_available", "executable_not_found"}:
            return _result("RUNNER_UNAVAILABLE", reason)
        if reason == "container_image_must_be_digest_pinned":
            return _result("INVALID_CONFIGURATION", reason)
        return _result("EXECUTION_FAILED", reason)
    except OSError:
        return _result("EXECUTION_FAILED", "temporary_project_io_failed")

    if observation.stdout_truncated or observation.stderr_truncated:
        status = "OUTPUT_TRUNCATED"
    elif observation.exit_code == 0:
        status = "EXECUTED_PASS"
    else:
        status = "EXECUTED_FAIL"

    result = _result(status)
    result.update({
        "exit_code": observation.exit_code,
        "duration_seconds": observation.duration_seconds,
        "container_image": configured_image,
        "container_isolation": observation.isolation,
        "compiler_version": compiler_version,
        "source_tree_sha256": source_digest.hexdigest(),
        "test_harness_sha256": test_digest,
        "stdout_sha256": observation.stdout_sha256,
        "stderr_sha256": observation.stderr_sha256,
        "stdout_truncated": observation.stdout_truncated,
        "stderr_truncated": observation.stderr_truncated,
        "stdout_excerpt": observation.stdout[:16_384],
        "stderr_excerpt": observation.stderr[:16_384],
        "test_passed": observation.exit_code == 0 and status == "EXECUTED_PASS",
        "required_next_step": "independent_review_of_harness_and_observed_behavior",
    })
    return result
