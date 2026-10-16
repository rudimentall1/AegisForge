import hashlib
import shutil
import sys
from pathlib import Path

import pytest

from shared.sandbox import SandboxError, SandboxLimits, run_in_sandbox


def _docker_available():
    return shutil.which("docker") is not None


def test_none_is_rejected(tmp_path):
    with pytest.raises(SandboxError, match="no_execution_allowed"):
        run_in_sandbox(["echo", "hi"], SandboxLimits(), tmp_path, "none")


def test_process_echo_returns_stdout_hash(tmp_path):
    result = run_in_sandbox(
        [sys.executable, "-c", "print('hi')"],
        SandboxLimits(),
        tmp_path,
        "process",
    )
    assert result.exit_code == 0
    assert result.stdout_sha256 == hashlib.sha256(b"hi\n").hexdigest()
    assert result.stdout_truncated is False
    assert result.isolation == "process"


def test_process_timeout_raises(tmp_path):
    with pytest.raises(SandboxError, match="execution_timeout"):
        run_in_sandbox(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            SandboxLimits(timeout_seconds=1),
            tmp_path,
            "process",
        )


def test_process_memory_limit_is_enforced(tmp_path):
    result = run_in_sandbox(
        [sys.executable, "-c", "x = [0] * 10**9"],
        SandboxLimits(timeout_seconds=10, memory_mb=64),
        tmp_path,
        "process",
    )
    assert result.exit_code != 0


def test_process_output_is_bounded_and_truncated(tmp_path):
    result = run_in_sandbox(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 2000000)"],
        SandboxLimits(max_output_bytes=1024),
        tmp_path,
        "process",
    )
    assert result.exit_code == 0
    assert result.stdout_truncated is True
    assert result.stdout_sha256 == hashlib.sha256(b"x" * 1024).hexdigest()


@pytest.mark.skipif(not _docker_available(), reason="Docker is not installed")
def test_container_echo(tmp_path):
    result = run_in_sandbox(
        ["echo", "hi"],
        SandboxLimits(),
        tmp_path,
        "container",
    )
    assert result.exit_code == 0
    assert result.stdout_sha256 == hashlib.sha256(b"hi\n").hexdigest()
    assert result.isolation == "container"


@pytest.mark.parametrize("command", ["echo hi", None, ("echo", "hi")])
def test_command_must_be_list(command, tmp_path):
    with pytest.raises(SandboxError, match="command_must_be_list"):
        run_in_sandbox(command, SandboxLimits(), tmp_path, "process")


def test_empty_command_is_rejected(tmp_path):
    with pytest.raises(SandboxError, match="command_empty"):
        run_in_sandbox([], SandboxLimits(), tmp_path, "process")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"timeout_seconds": 0},
        {"timeout_seconds": 3601},
        {"memory_mb": 31},
        {"memory_mb": 16385},
        {"cpu_cores": 0},
        {"cpu_cores": 17},
        {"max_output_bytes": 1023},
        {"max_output_bytes": 10_000_001},
        {"network": "bridge"},
    ],
)
def test_limits_reject_invalid_values(kwargs):
    with pytest.raises(SandboxError):
        SandboxLimits(**kwargs)
