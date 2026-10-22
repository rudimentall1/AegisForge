"""Bounded subprocess adapter for one repository-owned synthetic fixture.

This is intentionally not a generic command runner or a security sandbox.
Callers choose only a fixed fixture mode; no argv, path, environment, or shell
command is accepted from an evidence bundle.
"""
from __future__ import annotations

import json
import math
import os
import platform
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from shared.synthetic_fixture import (
    PROCESS_INPUT_SCHEMA_VERSION,
    run_synthetic_fixture,
)

DEFAULT_TIMEOUT_SECONDS = 3.0
MAX_TIMEOUT_SECONDS = 5.0
CPU_LIMIT_SECONDS = 2
ADDRESS_SPACE_LIMIT_BYTES = 256 * 1024 * 1024
FILE_SIZE_LIMIT_BYTES = 1024 * 1024
OPEN_FILE_LIMIT = 16
MAX_CAPTURE_BYTES = 64 * 1024
MAX_INPUT_BYTES = 4096


class SyntheticFixtureRunnerError(RuntimeError):
    """Raised when the fixed synthetic subprocess cannot be verified."""


def _apply_child_resource_limits() -> None:
    """Apply POSIX limits before exec; deliberately unavailable elsewhere."""
    import resource

    limits = (
        (resource.RLIMIT_CPU, CPU_LIMIT_SECONDS, CPU_LIMIT_SECONDS),
        (
            resource.RLIMIT_AS,
            ADDRESS_SPACE_LIMIT_BYTES,
            ADDRESS_SPACE_LIMIT_BYTES,
        ),
        (
            resource.RLIMIT_FSIZE,
            FILE_SIZE_LIMIT_BYTES,
            FILE_SIZE_LIMIT_BYTES,
        ),
        (resource.RLIMIT_NOFILE, OPEN_FILE_LIMIT, OPEN_FILE_LIMIT),
        (resource.RLIMIT_CORE, 0, 0),
    )
    for resource_id, soft, hard in limits:
        resource.setrlimit(resource_id, (soft, hard))


def _kill_process_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass


def _capture_bounded(
    process: subprocess.Popen,
    *,
    deadline: float,
) -> tuple[bytes, bytes]:
    """Drain both pipes without allowing unbounded in-memory output capture."""
    assert process.stdout is not None and process.stderr is not None
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SyntheticFixtureRunnerError("synthetic_fixture_timeout")
            events = selector.select(timeout=min(remaining, 0.05))
            for key, _ in events:
                name = key.data
                current = buffers[name]
                read_size = min(4096, MAX_CAPTURE_BYTES - len(current) + 1)
                chunk = os.read(key.fileobj.fileno(), read_size)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if len(current) + len(chunk) > MAX_CAPTURE_BYTES:
                    raise SyntheticFixtureRunnerError(
                        f"synthetic_fixture_{name}_limit_exceeded"
                    )
                current.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SyntheticFixtureRunnerError("synthetic_fixture_timeout")
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise SyntheticFixtureRunnerError(
                "synthetic_fixture_timeout"
            ) from exc
    finally:
        selector.close()
    return bytes(buffers["stdout"]), bytes(buffers["stderr"])


def run_synthetic_fixture_subprocess(
    mode: str,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict:
    """Run only the fixed accounting fixture in a resource-bounded child process.

    The timeout is capped, the child receives a minimal environment and temporary
    working directory, and both output streams have hard capture limits. POSIX
    CPU, address-space, file-size, open-file, and core-dump limits are applied.
    The process has no shell and its script path is fixed by this package.

    Important: the temporary working directory is not a filesystem sandbox, and
    this implementation does not create a network namespace or otherwise enforce
    network isolation. It must not be used to execute target code or bundle argv.
    """
    if not isinstance(mode, str) or mode not in {"control", "countertest"}:
        raise SyntheticFixtureRunnerError("synthetic_fixture_mode_not_allowed")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(float(timeout_seconds))
        or timeout_seconds <= 0
        or timeout_seconds > MAX_TIMEOUT_SECONDS
    ):
        raise SyntheticFixtureRunnerError("synthetic_fixture_timeout_invalid")
    if os.name != "posix":
        raise SyntheticFixtureRunnerError("synthetic_fixture_posix_limits_required")

    script_path = Path(__file__).with_name("synthetic_fixture.py")
    if script_path.is_symlink() or not script_path.is_file():
        raise SyntheticFixtureRunnerError("synthetic_fixture_script_unavailable")
    try:
        script_path = script_path.resolve(strict=True)
    except OSError as exc:
        raise SyntheticFixtureRunnerError(
            "synthetic_fixture_script_unavailable"
        ) from exc
    if script_path.stat().st_size > 64 * 1024:
        raise SyntheticFixtureRunnerError("synthetic_fixture_script_size_limit")

    request = {
        "schema_version": PROCESS_INPUT_SCHEMA_VERSION,
        "mode": mode,
    }
    input_bytes = json.dumps(
        request,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    if len(input_bytes) > MAX_INPUT_BYTES:
        raise SyntheticFixtureRunnerError("synthetic_fixture_input_limit_exceeded")

    expected = run_synthetic_fixture(mode)
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="aegisforge-synthetic-") as workdir:
            environment = {"HOME": workdir, "TMPDIR": workdir}
            command = [
                sys.executable,
                "-I",
                str(script_path),
                "--subprocess-run",
                mode,
            ]
            try:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=workdir,
                    env=environment,
                    close_fds=True,
                    start_new_session=True,
                    preexec_fn=_apply_child_resource_limits,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise SyntheticFixtureRunnerError(
                    "synthetic_fixture_spawn_failed"
                ) from exc

            try:
                assert process.stdin is not None
                process.stdin.write(input_bytes)
                process.stdin.close()
                stdout_bytes, stderr_bytes = _capture_bounded(
                    process, deadline=started + float(timeout_seconds)
                )
                exit_code = process.returncode
            except Exception:
                _kill_process_group(process)
                raise
            finally:
                if process.stdin is not None:
                    process.stdin.close()
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()

    except SyntheticFixtureRunnerError:
        raise
    except (OSError, ValueError) as exc:
        raise SyntheticFixtureRunnerError(
            "synthetic_fixture_process_failed"
        ) from exc

    elapsed_ms = int((time.monotonic() - started) * 1000)
    if exit_code != expected["exit_code"]:
        raise SyntheticFixtureRunnerError("synthetic_fixture_exit_code_mismatch")
    if stdout_bytes != expected["stdout_bytes"]:
        raise SyntheticFixtureRunnerError("synthetic_fixture_stdout_mismatch")
    if stderr_bytes != expected["stderr_bytes"]:
        raise SyntheticFixtureRunnerError("synthetic_fixture_stderr_mismatch")

    toolchain = {
        "python": platform.python_version(),
        "fixture": expected["schema_version"],
        "runner": "aegisforge-fixed-synthetic-subprocess-v1",
        "wall_timeout_seconds": str(float(timeout_seconds)),
        "cpu_limit_seconds": str(CPU_LIMIT_SECONDS),
        "address_space_limit_bytes": str(ADDRESS_SPACE_LIMIT_BYTES),
        "file_size_limit_bytes": str(FILE_SIZE_LIMIT_BYTES),
        "open_file_limit": str(OPEN_FILE_LIMIT),
        "network_isolation": "not_enforced",
        "filesystem_isolation": "not_enforced",
    }
    result = dict(expected)
    result.update({
        "input_bytes": input_bytes,
        "stdout_bytes": stdout_bytes,
        "stderr_bytes": stderr_bytes,
        "exit_code": exit_code,
        "argv": command,
        "toolchain": toolchain,
        "subprocess_started": True,
        "execution_mode": "fixed_fixture_subprocess",
        "execution": {
            "status": "PASS",
            "elapsed_ms": elapsed_ms,
            "exit_code_matches_fixed_fixture": True,
            "stdout_matches_fixed_fixture": True,
            "stderr_matches_fixed_fixture": True,
            "shell_used": False,
            "command_source": "repository_constant",
            "environment_allowlisted": True,
            "temporary_working_directory": True,
            "resource_limits_applied": True,
            "resource_limits": {
                "wall_timeout_seconds": float(timeout_seconds),
                "cpu_seconds": CPU_LIMIT_SECONDS,
                "address_space_bytes": ADDRESS_SPACE_LIMIT_BYTES,
                "file_size_bytes": FILE_SIZE_LIMIT_BYTES,
                "open_files": OPEN_FILE_LIMIT,
                "core_dumps": 0,
                "stdout_capture_bytes": MAX_CAPTURE_BYTES,
                "stderr_capture_bytes": MAX_CAPTURE_BYTES,
            },
            "network_isolation_enforced": False,
            "filesystem_isolation_enforced": False,
            "scope_note": (
                "Fixed synthetic fixture only; not a security sandbox and not "
                "approved for target code or bundle-provided commands."
            ),
        },
    })
    return result
