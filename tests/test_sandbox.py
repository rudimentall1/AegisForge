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
    assert result.stdout == "hi\n"
    assert result.stderr == ""
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


def test_container_runner_requires_a_digest_pinned_image(tmp_path):
    from shared.sandbox import run_in_container

    with pytest.raises(SandboxError, match="container_image_must_be_digest_pinned"):
        run_in_container(
            ["forge", "test"],
            SandboxLimits(),
            tmp_path,
            image="ghcr.io/foundry-rs/foundry:stable",
        )


def test_container_runner_uses_hardened_offline_docker_defaults(monkeypatch, tmp_path):
    import shared.sandbox as sandbox

    observed = {}
    image = "ghcr.io/foundry-rs/foundry@sha256:" + ("a" * 64)

    def fake_bounded_run(command, **kwargs):
        observed["command"] = command
        observed["kwargs"] = kwargs
        return sandbox.SandboxResult(
            exit_code=0,
            stdout_sha256=hashlib.sha256(b"ok").hexdigest(),
            stderr_sha256=hashlib.sha256(b"").hexdigest(),
            stdout_truncated=False,
            stderr_truncated=False,
            duration_seconds=0.1,
            isolation="container",
            stdout="ok",
            stderr="",
        )

    monkeypatch.setattr(sandbox.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(sandbox, "_bounded_run", fake_bounded_run)
    result = sandbox.run_in_container(
        ["forge", "test", "--offline"],
        SandboxLimits(timeout_seconds=30, memory_mb=1024, cpu_cores=2),
        tmp_path,
        image=image,
    )
    command = observed["command"]
    assert result.stdout == "ok"
    assert observed["kwargs"]["isolation"] == "container"
    assert "--network=none" in command
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges" in command
    assert "--pids-limit=64" in command
    assert "--memory-swap=1024m" in command
    assert "--init" in command
    assert "--pull=never" in command
    assert f"type=bind,src={tmp_path.resolve()},dst=/work,readonly" in command
    assert command[-4:] == [image, "forge", "test", "--offline"]


def test_container_runner_rejects_invalid_image_digest(monkeypatch, tmp_path):
    from shared.sandbox import run_in_container

    monkeypatch.setattr("shared.sandbox.shutil.which", lambda name: "/usr/bin/docker")
    with pytest.raises(SandboxError, match="container_image_must_be_digest_pinned"):
        run_in_container(
            ["forge", "test"],
            SandboxLimits(),
            tmp_path,
            image="ghcr.io/foundry-rs/foundry@sha256:short",
        )


def test_container_runner_kills_container_after_timeout(monkeypatch, tmp_path):
    import shared.sandbox as sandbox

    image = "ghcr.io/foundry-rs/foundry@sha256:" + ("c" * 64)
    cleanup_commands = []

    def timeout(*args, **kwargs):
        raise SandboxError("execution_timeout")

    def fake_subprocess_run(command, **kwargs):
        cleanup_commands.append(command)
        return sandbox.subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(sandbox.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(sandbox, "_bounded_run", timeout)
    monkeypatch.setattr(sandbox.subprocess, "run", fake_subprocess_run)

    with pytest.raises(SandboxError, match="execution_timeout"):
        sandbox.run_in_container(
            ["test"],
            SandboxLimits(timeout_seconds=1),
            tmp_path,
            image=image,
            entrypoint="forge",
        )

    assert len(cleanup_commands) == 2
    assert cleanup_commands[0][:2] == ["/usr/bin/docker", "kill"]
    assert cleanup_commands[1][:3] == ["/usr/bin/docker", "rm", "-f"]
    assert cleanup_commands[0][2] == cleanup_commands[1][3]


def test_container_runner_streams_workspace_file_to_stdin(monkeypatch, tmp_path):
    import shared.sandbox as sandbox

    image = "ghcr.io/foundry-rs/foundry@sha256:" + ("b" * 64)
    input_path = tmp_path / "compiler-input.json"
    input_path.write_text('{"language":"Solidity"}', encoding="utf-8")
    observed = {}

    def fake_bounded_run(command, **kwargs):
        observed["command"] = command
        observed["stdin"] = kwargs["stdin_file"].read()
        return sandbox.SandboxResult(
            exit_code=0,
            stdout_sha256=hashlib.sha256(b"{}").hexdigest(),
            stderr_sha256=hashlib.sha256(b"").hexdigest(),
            stdout_truncated=False,
            stderr_truncated=False,
            duration_seconds=0.1,
            isolation="container",
            stdout="{}",
            stderr="",
        )

    monkeypatch.setattr(sandbox.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(sandbox, "_bounded_run", fake_bounded_run)
    result = sandbox.run_in_container(
        ["--standard-json"],
        SandboxLimits(timeout_seconds=30, memory_mb=1024, cpu_cores=2),
        tmp_path,
        image=image,
        entrypoint="/work/.aegisforge/solc",
        stdin_path=input_path,
    )
    assert result.exit_code == 0
    assert observed["stdin"] == b'{"language":"Solidity"}'
    assert "-i" in observed["command"]


def test_container_runner_rejects_stdin_outside_workspace(monkeypatch, tmp_path):
    from shared.sandbox import run_in_container

    image = "ghcr.io/foundry-rs/foundry@sha256:" + ("d" * 64)
    outside = tmp_path.parent / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    monkeypatch.setattr("shared.sandbox.shutil.which", lambda name: "/usr/bin/docker")
    with pytest.raises(SandboxError, match="stdin_path_invalid"):
        run_in_container(
            ["--standard-json"],
            SandboxLimits(),
            tmp_path,
            image=image,
            stdin_path=outside,
        )
