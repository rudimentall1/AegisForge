"""Fail-closed bubblewrap backend for the fixed synthetic fixture only.

This is deliberately not a general target-code runner. It uses a private
network namespace and a minimal read-only filesystem view, then performs
in-sandbox checks before invoking the repository-owned fixture. If bubblewrap
or its required isolation primitives are unavailable, execution fails closed.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from shared.synthetic_fixture import run_synthetic_fixture
from shared.synthetic_fixture_runner import (
    MAX_CAPTURE_BYTES,
    MAX_TIMEOUT_SECONDS,
    _capture_bounded,
    _kill_process_group,
    SyntheticFixtureRunnerError,
)

DEFAULT_TIMEOUT_SECONDS = 3.0


class IsolatedFixtureRunnerError(RuntimeError):
    """Raised when enforced fixture isolation cannot be established."""


# Constant wrapper: no dossier field, command, path, or code is interpolated
# into the executed Python program. Only validated mode and a random probe
# filename are passed as fixed argv/environment values.
_SANDBOX_WRAPPER = r"""
import os
import runpy
import sys

expected_net_ns = int(os.environ["AEGISFORGE_EXPECTED_NET_NS"])
if os.stat("/proc/self/ns/net").st_ino == expected_net_ns:
    sys.stderr.write("sandbox_network_namespace_not_isolated\\n")
    raise SystemExit(78)

probe = "/usr/." + os.environ["AEGISFORGE_WRITE_PROBE"]
try:
    with open(probe, "xb") as handle:
        handle.write(b"must-not-write")
except OSError:
    pass
else:
    try:
        os.unlink(probe)
    finally:
        sys.stderr.write("sandbox_system_filesystem_writable\\n")
        raise SystemExit(78)

try:
    with open("/tmp/aegisforge-write-probe", "wb") as handle:
        handle.write(b"ok")
except OSError:
    sys.stderr.write("sandbox_tmp_not_writable\\n")
    raise SystemExit(78)

mode = sys.argv[1]
sys.argv = ["/fixture.py", "--subprocess-run", mode]
runpy.run_path("/fixture.py", run_name="__main__")
"""


def _build_bwrap_command(
    *,
    bwrap_path: str,
    python_path: str,
    fixture_path: str,
    mode: str,
    expected_net_ns: int,
    write_probe: str,
) -> list[str]:
    """Build a fixed mount/namespace profile; caller validates mode first."""
    command = [
        bwrap_path,
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--cap-drop", "ALL",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind-try", "/opt", "/opt",
        "--ro-bind-try", "/lib", "/lib",
        "--ro-bind-try", "/lib64", "/lib64",
        "--dir", "/etc",
        "--ro-bind-try", "/etc/ld.so.cache", "/etc/ld.so.cache",
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        "--dir", "/work",
        "--ro-bind", fixture_path, "/fixture.py",
        "--chdir", "/work",
        "--clearenv",
        "--setenv", "HOME", "/tmp",
        "--setenv", "TMPDIR", "/tmp",
        "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
        "--setenv", "PYTHONNOUSERSITE", "1",
        "--setenv", "AEGISFORGE_EXPECTED_NET_NS", str(expected_net_ns),
        "--setenv", "AEGISFORGE_WRITE_PROBE", write_probe,
        "--",
        python_path,
        "-I",
        "-c",
        _SANDBOX_WRAPPER,
        mode,
    ]
    return command


def run_isolated_synthetic_fixture(
    mode: str,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict:
    """Run only the fixed fixture inside verified bubblewrap isolation.

    PASS is returned only after the child confirms a different network
    namespace, confirms that the mounted system tree is not writable, and
    produces the exact stdout/stderr/exit code of the repository fixture.
    This is still fixture-harness evidence, not target reproduction.
    """
    if not isinstance(mode, str) or mode not in {"control", "countertest"}:
        raise IsolatedFixtureRunnerError("isolated_fixture_mode_not_allowed")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or timeout_seconds <= 0
        or timeout_seconds > MAX_TIMEOUT_SECONDS
    ):
        raise IsolatedFixtureRunnerError("isolated_fixture_timeout_invalid")
    if not sys.platform.startswith("linux"):
        raise IsolatedFixtureRunnerError("bubblewrap_linux_required")

    bwrap_path = shutil.which("bwrap")
    if not bwrap_path:
        raise IsolatedFixtureRunnerError("bubblewrap_unavailable_fail_closed")

    fixture_path = Path(__file__).with_name("synthetic_fixture.py")
    if fixture_path.is_symlink() or not fixture_path.is_file():
        raise IsolatedFixtureRunnerError("isolated_fixture_source_unavailable")
    try:
        fixture_path = fixture_path.resolve(strict=True)
        fixture_path.stat()
    except OSError as exc:
        raise IsolatedFixtureRunnerError("isolated_fixture_source_unavailable") from exc

    expected = run_synthetic_fixture(mode)
    expected_net_ns = os.stat("/proc/self/ns/net").st_ino
    write_probe = f"aegisforge-probe-{os.getpid()}-{time.time_ns()}"
    command = _build_bwrap_command(
        bwrap_path=bwrap_path,
        python_path=str(Path(sys.executable).resolve()),
        fixture_path=str(fixture_path),
        mode=mode,
        expected_net_ns=expected_net_ns,
        write_probe=write_probe,
    )
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
            shell=False,
            env={},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise IsolatedFixtureRunnerError("bubblewrap_start_failed_fail_closed") from exc

    request = {
        "schema_version": "aegisforge-synthetic-fixture-process-input-v1",
        "mode": mode,
    }
    input_bytes = json.dumps(
        request, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    try:
        assert process.stdin is not None
        process.stdin.write(input_bytes)
        process.stdin.close()
        stdout_bytes, stderr_bytes = _capture_bounded(
            process, deadline=started + float(timeout_seconds)
        )
        exit_code = process.returncode
    except Exception as exc:
        _kill_process_group(process)
        if isinstance(exc, (SyntheticFixtureRunnerError, IsolatedFixtureRunnerError)):
            raise
        raise IsolatedFixtureRunnerError("bubblewrap_execution_failed_fail_closed") from exc
    finally:
        if process.stdin is not None:
            process.stdin.close()
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()

    if exit_code != expected["exit_code"]:
        detail = stderr_bytes.decode("utf-8", errors="replace")[:512]
        raise IsolatedFixtureRunnerError(
            f"bubblewrap_child_failed:exit={exit_code}:stderr={detail}"
        )
    if stdout_bytes != expected["stdout_bytes"] or stderr_bytes != expected["stderr_bytes"]:
        raise IsolatedFixtureRunnerError("bubblewrap_fixture_output_mismatch")
    elapsed_ms = int((time.monotonic() - started) * 1000)
    result = dict(expected)
    result.update({
        "input_bytes": input_bytes,
        "stdout_bytes": stdout_bytes,
        "stderr_bytes": stderr_bytes,
        "exit_code": exit_code,
        "argv": command,
        "subprocess_started": True,
        "execution_mode": "bubblewrap_isolated_fixed_fixture",
        "toolchain": {
            **expected["toolchain"],
            "runner": "aegisforge-bubblewrap-fixed-fixture-v1",
            "sandbox": "bubblewrap",
            "network_isolation": "enforced_and_namespace_checked",
            "filesystem_isolation": "read_only_system_tree_and_private_tmp_checked",
        },
        "execution": {
            "status": "PASS",
            "elapsed_ms": elapsed_ms,
            "shell_used": False,
            "command_source": "repository_constant",
            "environment_allowlisted": True,
            "network_isolation_enforced": True,
            "filesystem_isolation_enforced": True,
            "network_namespace_checked": True,
            "read_only_system_tree_checked": True,
            "private_tmp_write_checked": True,
            "resource_limits_applied": True,
            "resource_limits": {
                "wall_timeout_seconds": float(timeout_seconds),
                "cpu_seconds": "fixture_rlimit",
                "address_space_bytes": "fixture_rlimit",
                "file_size_bytes": "fixture_rlimit",
                "open_files": "fixture_rlimit",
                "core_dumps": 0,
                "stdout_capture_bytes": MAX_CAPTURE_BYTES,
                "stderr_capture_bytes": MAX_CAPTURE_BYTES,
            },
            "scope_note": (
                "Verified bubblewrap isolation for the fixed repository-owned "
                "synthetic fixture only; this is not target reproduction."
            ),
        },
    })
    return result
