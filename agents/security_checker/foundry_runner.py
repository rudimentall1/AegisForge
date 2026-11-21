from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

from shared.sandbox import SandboxError, SandboxLimits, run_in_container
from shared.solc_toolchain import resolve_solc_binary


MAX_SOURCE_FILES = 500
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_TEST_BYTES = 256 * 1024
MAX_OUTPUT_BYTES = 512 * 1024
MAX_COMPILER_BYTES = 128 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 300
_TEST_PATH = "test/AegisForgeValidation.t.sol"


def _probe_solc_binary(path: Path, expected_version: str) -> str:
    try:
        completed = subprocess.run(
            [str(path), "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "COMPILER_UNAVAILABLE"
    output = (completed.stdout or "") + (completed.stderr or "")
    match = re.search(r"Version:\s*(\d+\.\d+\.\d+)", output)
    if completed.returncode != 0 or match is None:
        return "COMPILER_UNAVAILABLE"
    if match.group(1) != expected_version:
        return "COMPILER_VERSION_MISMATCH"
    return "OK"


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _summarize_foundry_output(stdout: str) -> dict:
    try:
        payload = json.loads(stdout)
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
        return {"valid": False, "total": 0, "passed": 0, "failed": 0, "skipped": 0, "test_statuses": {}}
    if not isinstance(payload, dict):
        return {"valid": False, "total": 0, "passed": 0, "failed": 0, "skipped": 0, "test_statuses": {}}

    counts = {
        "valid": True, "total": 0, "passed": 0, "failed": 0, "skipped": 0,
        "test_statuses": {},
    }
    for suite in payload.values():
        if not isinstance(suite, dict):
            continue
        tests = suite.get("test_results")
        if tests is None:
            continue
        if not isinstance(tests, dict):
            counts["valid"] = False
            continue
        for test_name, test_result in tests.items():
            if not isinstance(test_name, str) or not test_name:
                counts["valid"] = False
                continue
            if not isinstance(test_result, dict):
                counts["valid"] = False
                continue
            status = test_result.get("status")
            if not isinstance(status, str) or status not in {"Success", "Failure", "Skipped"}:
                counts["valid"] = False
                continue
            counts["total"] += 1
            test_name_base = test_name.split("(", 1)[0]
            if not test_name_base or test_name_base in counts["test_statuses"]:
                counts["valid"] = False
                continue
            counts["test_statuses"][test_name_base] = status
            if status == "Success":
                counts["passed"] += 1
            elif status == "Failure":
                counts["failed"] += 1
            else:
                counts["skipped"] += 1
    return counts


def _result(status: str, error: str | None = None) -> dict:
    empty_digest = _sha256(b"")
    result = {
        "schema": "aegisforge.foundry_execution.v1",
        "status": status,
        "dynamic_verified": False,
        "confirmed": False,
        "validation_scope": "local_isolated_harness_execution",
        "network_access": False,
        "host_filesystem_access": False,
        "project_mount_read_only": True,
        "transactions_sent": False,
        # A NOT_RUN result still carries a deterministic empty artifact set so
        # the Worker can preserve the failed admission/configuration attempt.
        "command": ["forge", "test", "--offline"],
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "stdout_sha256": empty_digest,
        "stderr_sha256": empty_digest,
        "stdout_truncated": False,
        "stderr_truncated": False,
        "test_statuses": {},
        "test_counts": {"total": 0, "passed": 0, "failed": 0, "skipped": 0},
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
        path_parts = name.split("/")
        relative = PurePosixPath(name)
        if (
            relative.is_absolute()
            or not relative.parts
            or any(part in ("", ".", "..") for part in path_parts)
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
        r"ghcr\.io/foundry-rs/foundry@sha256:[0-9a-f]{64}",
        configured_image,
    ):
        return _result("INVALID_CONFIGURATION", "official_foundry_image_digest_required")
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
    if platform.system() != "Linux":
        return _result("COMPILER_UNAVAILABLE", "linux_compiler_artifact_required")

    compiler_installed = False
    compiler_path = resolve_solc_binary(compiler_version)
    if compiler_path is None:
        auto_install = os.getenv("AEGISFORGE_AUTO_INSTALL_SOLC", "0").strip().lower()
        if auto_install in {"1", "true", "yes"}:
            solc_select = shutil.which("solc-select")
            if not solc_select:
                return _result("COMPILER_UNAVAILABLE", "solc_select_not_available")
            try:
                install = subprocess.run(
                    [solc_select, "install", compiler_version],
                    capture_output=True,
                    text=True,
                    timeout=180,
                    check=False,
                    shell=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                return _result("COMPILER_UNAVAILABLE", "solc_install_failed")
            if install.returncode != 0:
                return _result("COMPILER_UNAVAILABLE", "solc_install_failed")
            compiler_installed = True
            compiler_path = resolve_solc_binary(compiler_version)
    if compiler_path is None:
        return _result("COMPILER_UNAVAILABLE", "required_solc_binary_not_installed")

    try:
        compiler_size = compiler_path.stat().st_size
        if compiler_size <= 0 or compiler_size > MAX_COMPILER_BYTES:
            return _result("COMPILER_UNAVAILABLE", "required_solc_binary_size_invalid")
        compiler_bytes = compiler_path.read_bytes()
    except OSError:
        return _result("COMPILER_UNAVAILABLE", "required_solc_binary_unreadable")
    compiler_digest = _sha256(compiler_bytes)
    test_digest = _sha256(test_bytes)
    # Probe an exact byte-for-byte copy of the compiler that will be mounted
    # into the container. This avoids a path-swap between version check and use.
    try:
        with tempfile.TemporaryDirectory(prefix="aegisforge-solc-probe-") as probe_dir:
            compiler_probe = Path(probe_dir) / "solc"
            compiler_probe.write_bytes(compiler_bytes)
            compiler_probe.chmod(0o555)
            compiler_status = _probe_solc_binary(compiler_probe, compiler_version)
    except OSError:
        return _result("COMPILER_UNAVAILABLE", "required_solc_binary_probe_setup_failed")
    if compiler_status != "OK":
        return _result(compiler_status, "required_solc_binary_probe_failed")

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
        "test",
        "--root",
        "/work",
        "--offline",
        "--use",
        "/work/.aegisforge/solc",
        "--match-path",
        _TEST_PATH,
        "--match-test",
        "^test.*$",
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
            (root / "lib").mkdir()
            compiler_dir = root / ".aegisforge"
            compiler_dir.mkdir()
            compiler_copy = compiler_dir / "solc"
            compiler_copy.write_bytes(compiler_bytes)
            compiler_copy.chmod(0o555)
            for relative_name, content in normalized_sources.items():
                destination = root / "src" / PurePosixPath(relative_name)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(content, encoding="utf-8")
            (root / _TEST_PATH).write_text(test_source, encoding="utf-8")
            (root / "foundry.toml").write_text(foundry_config, encoding="utf-8")
            # Docker runs as UID/GID 65532; TemporaryDirectory defaults to 0700.
            # Make only this disposable project readable before mounting it read-only.
            root.chmod(0o755)

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
                entrypoint="forge",
            )
    except SandboxError as exc:
        reason = str(exc)
        if reason == "execution_timeout":
            failure = _result("TIMEOUT", reason)
            failure["exit_code"] = -9
        elif reason in {"docker_not_available", "executable_not_found"}:
            failure = _result("RUNNER_UNAVAILABLE", reason)
        elif reason == "container_image_must_be_digest_pinned":
            failure = _result("INVALID_CONFIGURATION", reason)
        else:
            failure = _result("EXECUTION_FAILED", reason)
        failure["command"] = ["forge", *command]
        failure["container_image"] = configured_image
        failure["compiler_sha256"] = compiler_digest
        return failure
    except OSError:
        failure = _result("EXECUTION_FAILED", "temporary_project_io_failed")
        failure["command"] = ["forge", *command]
        failure["container_image"] = configured_image
        failure["compiler_sha256"] = compiler_digest
        return failure

    test_counts = _summarize_foundry_output(observation.stdout)
    if observation.exit_code == 125:
        status = "RUNNER_UNAVAILABLE"
        error = "container_start_failed"
    elif observation.exit_code in {126, 127}:
        status = "TOOL_UNAVAILABLE"
        error = "foundry_executable_unavailable"
    elif observation.stdout_truncated or observation.stderr_truncated:
        status = "OUTPUT_TRUNCATED"
        error = None
    elif not test_counts["valid"]:
        status = "INVALID_OUTPUT"
        error = "foundry_json_output_invalid"
    elif test_counts["total"] == 0:
        status = "NO_TESTS"
        error = "no_foundry_tests_executed"
    elif test_counts["failed"] > 0:
        status = "EXECUTED_FAIL"
        error = None
    elif test_counts["skipped"] > 0 and test_counts["passed"] > 0:
        status = "PARTIAL_EXECUTION"
        error = "some_foundry_tests_were_skipped"
    elif test_counts["skipped"] > 0:
        status = "SKIPPED"
        error = "foundry_tests_were_skipped"
    elif observation.exit_code != 0:
        status = "EXECUTION_FAILED"
        error = "foundry_exit_code_nonzero_without_failed_test_record"
    elif test_counts["passed"] == 0:
        status = "NO_TESTS"
        error = "no_passing_foundry_tests"
    else:
        status = "EXECUTED_PASS"
        error = None

    result = _result(status, error)
    result.update({
        "command": ["forge", *command],
        "exit_code": observation.exit_code,
        "duration_seconds": observation.duration_seconds,
        "container_image": configured_image,
        "container_image_provenance_verified": False,
        "container_isolation": observation.isolation,
        "compiler_version": compiler_version,
        "compiler_installed": compiler_installed,
        "compiler_selection_mode": "explicit_binary_path_no_global_switch",
        "compiler_binary_sha256": compiler_digest,
        "compiler_binary_provenance_verified": False,
        "source_tree_sha256": source_digest.hexdigest(),
        "test_harness_sha256": test_digest,
        "stdout_sha256": observation.stdout_sha256,
        "stderr_sha256": observation.stderr_sha256,
        "stdout_truncated": observation.stdout_truncated,
        "stderr_truncated": observation.stderr_truncated,
        "stdout_excerpt": observation.stdout[:16_384],
        "stderr_excerpt": observation.stderr[:16_384],
        # Full bounded capture is passed to the evidence persister, then removed
        # from the queue task result after the raw artifacts are stored.
        "stdout": observation.stdout,
        "stderr": observation.stderr,
        "test_statuses": dict(sorted(test_counts["test_statuses"].items())),
        "test_counts": {
            "total": test_counts["total"],
            "passed": test_counts["passed"],
            "failed": test_counts["failed"],
            "skipped": test_counts["skipped"],
        },
        "test_passed": (
            observation.exit_code == 0
            and status == "EXECUTED_PASS"
            and test_counts["passed"] > 0
        ),
        "required_next_step": "independent_review_of_harness_and_observed_behavior",
    })
    return result
