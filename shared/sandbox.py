"""Bounded subprocess/container execution for authorized local research.

This module does not provide a complete security sandbox:
- process: subprocess plus POSIX resource limits; not a filesystem or syscall boundary.
- container: Docker with no network, read-only source mount/rootfs and dropped caps;
  the default Docker seccomp profile remains enabled, but no custom profile is
  configured, so this is not a complete sandbox.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import selectors
import signal
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


class SandboxError(RuntimeError):
    """Raised when sandbox execution is invalid or cannot be safely completed."""


@dataclass(frozen=True)
class SandboxLimits:
    timeout_seconds: int = 60
    memory_mb: int = 512
    cpu_cores: int = 1
    max_output_bytes: int = 1_000_000
    network: str = "none"

    def __post_init__(self) -> None:
        checks = (
            ("timeout_seconds", self.timeout_seconds, 1, 3600),
            ("memory_mb", self.memory_mb, 32, 16384),
            ("cpu_cores", self.cpu_cores, 1, 16),
            ("max_output_bytes", self.max_output_bytes, 1024, 10_000_000),
        )
        for name, value, low, high in checks:
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise SandboxError(f"invalid_{name}")
        if self.network != "none":
            raise SandboxError("network_mode_not_supported")


@dataclass(frozen=True)
class SandboxResult:
    exit_code: int
    stdout_sha256: str
    stderr_sha256: str
    stdout_truncated: bool
    stderr_truncated: bool
    duration_seconds: float
    isolation: str
    stdout: str = ""
    stderr: str = ""


def _validate_command(command: object) -> list[str]:
    if not isinstance(command, list):
        raise SandboxError("command_must_be_list")
    if not command:
        raise SandboxError("command_empty")
    if any(not isinstance(arg, str) or not arg or "\x00" in arg for arg in command):
        raise SandboxError("command_argument_invalid")
    return command


def _bounded_run(
    command: list[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    max_output_bytes: int,
    preexec_fn=None,
    isolation: str,
    stdin_file=None,
) -> SandboxResult:
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            cwd=str(cwd),
            stdin=stdin_file if stdin_file is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            preexec_fn=preexec_fn,
            start_new_session=(os.name == "posix"),
        )
    except FileNotFoundError as exc:
        raise SandboxError("executable_not_found") from exc
    except (OSError, ValueError) as exc:
        raise SandboxError("process_start_failed") from exc

    assert process.stdout is not None and process.stderr is not None
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    truncated = {"stdout": False, "stderr": False}
    streams = {process.stdout: "stdout", process.stderr: "stderr"}
    selector = selectors.DefaultSelector()
    for stream in streams:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)

    deadline = started + timeout_seconds
    timed_out = False
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            events = selector.select(min(remaining, 0.1))
            for key, _ in events:
                stream = key.fileobj
                name = streams[stream]
                try:
                    chunk = os.read(stream.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                buffer = buffers[name]
                room = max_output_bytes - len(buffer)
                if room > 0:
                    buffer.extend(chunk[:room])
                if len(chunk) > max(room, 0):
                    truncated[name] = True
            if process.poll() is not None and not events and not selector.get_map():
                break
        if timed_out:
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except ProcessLookupError:
                pass
            process.wait()
            raise SandboxError("execution_timeout")
        exit_code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
    except subprocess.TimeoutExpired as exc:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass
        process.wait()
        raise SandboxError("execution_timeout") from exc
    finally:
        selector.close()
        for stream in streams:
            if not stream.closed:
                stream.close()

    return SandboxResult(
        exit_code=exit_code,
        stdout_sha256=hashlib.sha256(buffers["stdout"]).hexdigest(),
        stderr_sha256=hashlib.sha256(buffers["stderr"]).hexdigest(),
        stdout_truncated=truncated["stdout"],
        stderr_truncated=truncated["stderr"],
        duration_seconds=max(0.0, time.monotonic() - started),
        isolation=isolation,
        stdout=bytes(buffers["stdout"]).decode("utf-8", errors="replace"),
        stderr=bytes(buffers["stderr"]).decode("utf-8", errors="replace"),
    )


def run_in_sandbox(
    command: list[str],
    limits: SandboxLimits,
    source_root: Path,
    isolation: str,
) -> SandboxResult:
    """Run a command with bounded output and explicitly limited isolation."""
    argv = _validate_command(command)
    if not isinstance(limits, SandboxLimits):
        raise SandboxError("limits_invalid")
    if isolation == "none":
        raise SandboxError("no_execution_allowed")
    if isolation not in {"process", "container"}:
        raise SandboxError("isolation_invalid")
    try:
        root = Path(source_root).resolve(strict=True)
    except (OSError, TypeError, ValueError) as exc:
        raise SandboxError("source_root_invalid") from exc
    if not root.is_dir():
        raise SandboxError("source_root_not_directory")

    preexec_fn = None
    if isolation == "process":
        if os.name != "posix":
            raise SandboxError("process_rlimits_unavailable")
        try:
            import resource
        except ImportError as exc:
            raise SandboxError("process_rlimits_unavailable") from exc

        def apply_limits() -> None:
            memory = limits.memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
            cpu = limits.timeout_seconds
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
            resource.setrlimit(resource.RLIMIT_NPROC, (16, 16))

        preexec_fn = apply_limits
        return _bounded_run(
            argv,
            cwd=root,
            timeout_seconds=limits.timeout_seconds,
            max_output_bytes=limits.max_output_bytes,
            preexec_fn=preexec_fn,
            isolation="process",
        )

    docker = [
        "docker", "run", "--rm",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--user=nobody",
        f"--memory={limits.memory_mb}m",
        f"--cpus={limits.cpu_cores}",
        "--ulimit", "nofile=256:256",
        "--tmpfs", "/tmp:size=64m",
        "-v", f"{root}:/work:ro",
        "-w", "/work",
        "python:3.12-slim",
        *argv,
    ]
    try:
        return _bounded_run(
            docker,
            cwd=root,
            timeout_seconds=limits.timeout_seconds,
            max_output_bytes=limits.max_output_bytes,
            isolation="container",
        )
    except SandboxError as exc:
        if str(exc) == "executable_not_found":
            raise SandboxError("docker_not_available") from exc
        raise


def run_in_container(
    command: list[str],
    limits: SandboxLimits,
    source_root: Path,
    *,
    image: str,
    entrypoint: str | None = None,
    stdin_path: Path | None = None,
) -> SandboxResult:
    """Run a command in a digest-pinned, networkless Docker container.

    Docker's default seccomp profile remains enabled. This is a container
    boundary, not a claim of resistance to kernel or Docker-runtime escapes.
    """
    argv = _validate_command(command)
    if not isinstance(limits, SandboxLimits):
        raise SandboxError("limits_invalid")
    if (
        not isinstance(image, str)
        or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9./:_-]*@sha256:[0-9a-f]{64}",
            image,
        )
    ):
        raise SandboxError("container_image_must_be_digest_pinned")
    docker = shutil.which("docker")
    if not docker:
        raise SandboxError("docker_not_available")
    try:
        root = Path(source_root).resolve(strict=True)
    except (OSError, TypeError, ValueError) as exc:
        raise SandboxError("source_root_invalid") from exc
    if not root.is_dir():
        raise SandboxError("source_root_not_directory")
    input_file = None
    if stdin_path is not None:
        try:
            resolved_stdin = Path(stdin_path).resolve(strict=True)
            resolved_stdin.relative_to(root)
            if not resolved_stdin.is_file():
                raise SandboxError("stdin_path_invalid")
            input_file = resolved_stdin.open("rb")
        except SandboxError:
            raise
        except (OSError, TypeError, ValueError) as exc:
            raise SandboxError("stdin_path_invalid") from exc
    if entrypoint is not None and (
        not isinstance(entrypoint, str)
        or not re.fullmatch(r"[A-Za-z0-9_./-]+", entrypoint)
    ):
        raise SandboxError("container_entrypoint_invalid")

    container_name = f"aegisforge-run-{uuid.uuid4().hex}"
    docker_command = [
        docker,
        "run",
        "--rm",
        "--init",
        *(["-i"] if input_file is not None else []),
        "--name",
        container_name,
        "--pull=never",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=64",
        "--user=65532:65532",
        f"--memory={limits.memory_mb}m",
        f"--memory-swap={limits.memory_mb}m",
        f"--cpus={limits.cpu_cores}",
        "--ulimit", "nofile=256:256",
        "--ulimit", "nproc=64:64",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=128m",
        "--env=HOME=/tmp",
        "--mount", f"type=bind,src={root},dst=/work,readonly",
        "--workdir=/work",
    ]
    if entrypoint is not None:
        docker_command.append(f"--entrypoint={entrypoint}")
    docker_command.extend([image, *argv])
    try:
        try:
            return _bounded_run(
                docker_command,
                cwd=root,
                timeout_seconds=limits.timeout_seconds,
                max_output_bytes=limits.max_output_bytes,
                isolation="container",
                stdin_file=input_file,
            )
        except SandboxError as exc:
            if str(exc) == "execution_timeout":
                for cleanup_command in (
                    [docker, "kill", container_name],
                    [docker, "rm", "-f", container_name],
                ):
                    try:
                        subprocess.run(
                            cleanup_command,
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=5,
                            check=False,
                            shell=False,
                        )
                    except (OSError, subprocess.TimeoutExpired):
                        pass
            raise
    finally:
        if input_file is not None:
            input_file.close()
