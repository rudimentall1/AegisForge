"""Explicitly invoked, network-disabled Docker runner for reproduction contracts.

This module never runs bundle commands on the host. It requires a locally
available, digest-pinned image and runs with no network, no capabilities,
read-only container root, bounded resources, and a size-limited output tmpfs.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import tempfile
import uuid
from pathlib import Path

from shared.reproduction_contract import (
    ReproductionContractError,
    contract_sha256,
    validate_reproduction_contract,
)

MAX_WORKSPACE_FILES = 100_000
MAX_WORKSPACE_BYTES = 1024 * 1024 * 1024
DOCKER_START_TIMEOUT_SECONDS = 30
DOCKER_CLEANUP_TIMEOUT_SECONDS = 10
OUTPUT_COPY_TIMEOUT_SECONDS = 30


class ReproductionRunnerError(ValueError):
    """The runner input or execution environment is unsafe or invalid."""


def _walk_error(error: OSError) -> None:
    raise ReproductionRunnerError("workspace_walk_failed") from error


def _scan_workspace(root: Path) -> tuple[int, int]:
    total_bytes = 0
    file_count = 0
    for current, directories, files in os.walk(root, topdown=True, followlinks=False, onerror=_walk_error):
        current_path = Path(current)
        for directory in directories:
            item = current_path / directory
            if item.is_symlink():
                raise ReproductionRunnerError("workspace_symlink_rejected")
            try:
                mode = item.stat(follow_symlinks=False).st_mode
            except OSError as exc:
                raise ReproductionRunnerError("workspace_stat_failed") from exc
            if not stat.S_ISDIR(mode):
                raise ReproductionRunnerError("workspace_non_directory_entry_rejected")
        for filename in files:
            item = current_path / filename
            try:
                item_stat = item.stat(follow_symlinks=False)
            except OSError as exc:
                raise ReproductionRunnerError("workspace_stat_failed") from exc
            if stat.S_ISLNK(item_stat.st_mode):
                raise ReproductionRunnerError("workspace_symlink_rejected")
            if not stat.S_ISREG(item_stat.st_mode):
                raise ReproductionRunnerError("workspace_special_file_rejected")
            file_count += 1
            total_bytes += item_stat.st_size
            if file_count > MAX_WORKSPACE_FILES:
                raise ReproductionRunnerError("workspace_file_count_limit_exceeded")
            if total_bytes > MAX_WORKSPACE_BYTES:
                raise ReproductionRunnerError("workspace_size_limit_exceeded")
    return file_count, total_bytes


def _prepare_output_directory(output_dir: str | Path, workspace_root: Path) -> Path:
    raw = Path(output_dir)
    if raw.exists() or raw.is_symlink():
        raise ReproductionRunnerError("output_directory_must_not_exist")
    raw.parent.mkdir(parents=True, exist_ok=True)
    parent = raw.parent.resolve(strict=True)
    target = parent / raw.name
    if target.exists() or target.is_symlink():
        raise ReproductionRunnerError("output_directory_must_not_exist")
    if (
        target == workspace_root
        or target.is_relative_to(workspace_root)
        or workspace_root.is_relative_to(target)
    ):
        raise ReproductionRunnerError("output_directory_must_be_disjoint_from_workspace")
    target.mkdir(mode=0o700)
    return target


def _verify_outputs(output_dir: Path, expected_outputs: list[dict], max_bytes: int) -> dict:
    expected = {item["path"]: item["sha256"] for item in expected_outputs}
    actual_paths: set[str] = set()
    total_bytes = 0
    try:
        for current, directories, files in os.walk(output_dir, topdown=True, followlinks=False, onerror=_walk_error):
            current_path = Path(current)
            for directory in directories:
                candidate = current_path / directory
                if candidate.is_symlink():
                    raise ReproductionRunnerError("output_symlink_rejected")
                if not candidate.is_dir():
                    raise ReproductionRunnerError("output_non_directory_entry_rejected")
            for filename in files:
                candidate = current_path / filename
                if candidate.is_symlink():
                    raise ReproductionRunnerError("output_symlink_rejected")
                file_stat = candidate.stat(follow_symlinks=False)
                if not stat.S_ISREG(file_stat.st_mode):
                    raise ReproductionRunnerError("output_special_file_rejected")
                relative = candidate.relative_to(output_dir).as_posix()
                actual_paths.add(relative)
                total_bytes += file_stat.st_size
                if total_bytes > max_bytes:
                    raise ReproductionRunnerError("output_size_limit_exceeded")
        if actual_paths != set(expected):
            missing = sorted(set(expected) - actual_paths)
            extra = sorted(actual_paths - set(expected))
            raise ReproductionRunnerError(
                f"output_file_set_mismatch:missing={','.join(missing)}:extra={','.join(extra)}"
            )
        checked = []
        for relative_path, expected_digest in expected.items():
            candidate = output_dir.joinpath(*relative_path.split("/"))
            digest = hashlib.sha256()
            with candidate.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            actual_digest = digest.hexdigest()
            if actual_digest != expected_digest:
                raise ReproductionRunnerError(f"output_digest_mismatch:{relative_path}")
            checked.append({"path": relative_path, "sha256": actual_digest})
        return {"status": "PASS", "checked_outputs": checked, "total_bytes": total_bytes}
    except (OSError, ValueError) as exc:
        return {"status": "FAIL", "error": str(exc) or type(exc).__name__}


def _docker_call(docker_path: str, arguments: list[str], *, timeout: int, env: dict[str, str]):
    return subprocess.run(
        [docker_path, *arguments],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env=env,
    )


def _remove_container(docker_path: str, container_name: str, env: dict[str, str]) -> str:
    try:
        result = _docker_call(
            docker_path, ["rm", "-f", container_name],
            timeout=DOCKER_CLEANUP_TIMEOUT_SECONDS, env=env,
        )
        return "REMOVED" if result.returncode == 0 else "FAILED"
    except (subprocess.TimeoutExpired, OSError):
        return "FAILED"


def _stop_container(docker_path: str, container_name: str, env: dict[str, str]) -> None:
    try:
        _docker_call(
            docker_path, ["stop", "--time", "1", container_name],
            timeout=5, env=env,
        )
    except (subprocess.TimeoutExpired, OSError):
        pass


def run_reproduction_contract(
    contract_payload: object,
    bundle_root: str | Path,
    output_dir: str | Path,
    *,
    docker_binary: str = "docker",
) -> dict:
    """Run a validated contract in a bounded local Docker container.

    The caller must explicitly invoke this function. The input tree is copied
    into a temporary workspace, mounted read-only, and never modified in place.
    Container output is written to a size-limited tmpfs and copied out only after
    the container stops. The output directory must not already exist.
    """
    contract = validate_reproduction_contract(contract_payload)
    contract_digest = contract_sha256(contract)

    raw_root = Path(bundle_root)
    if raw_root.is_symlink():
        raise ReproductionRunnerError("workspace_root_must_not_be_symlink")
    try:
        root = raw_root.resolve(strict=True)
    except (OSError, ValueError) as exc:
        raise ReproductionRunnerError("workspace_root_missing_or_invalid") from exc
    if not root.is_dir():
        raise ReproductionRunnerError("workspace_root_must_be_directory")
    _scan_workspace(root)

    docker_path = shutil.which(docker_binary)
    if not docker_path:
        return {
            "status": "NOT_RUN",
            "reason": "docker_binary_not_available",
            "contract_sha256": contract_digest,
        }
    if not hasattr(os, "getuid") or not hasattr(os, "getgid"):
        return {
            "status": "NOT_RUN",
            "reason": "linux_posix_runner_required",
            "contract_sha256": contract_digest,
        }

    output_root = _prepare_output_directory(output_dir, root)
    container_name = "aegisforge-repro-" + uuid.uuid4().hex
    cleanup_status = "NOT_NEEDED"
    timed_out = False
    exit_code = None
    output_result = None
    execution_error = None

    try:
        with tempfile.TemporaryDirectory(prefix="aegisforge-reproduction-") as temporary:
            temporary_root = Path(temporary)
            workspace = temporary_root / "workspace"
            shutil.copytree(root, workspace, symlinks=True)
            _scan_workspace(workspace)

            source_path = workspace.joinpath(*contract["target"]["source_path"].split("/"))
            if not source_path.is_file() or source_path.is_symlink():
                raise ReproductionRunnerError("target_source_file_missing")
            working_directory = workspace
            if contract["working_directory"] != ".":
                working_directory = workspace.joinpath(*contract["working_directory"].split("/"))
            if not working_directory.is_dir() or working_directory.is_symlink():
                raise ReproductionRunnerError("working_directory_missing")

            env_file = temporary_root / "contract.env"
            with env_file.open("x", encoding="utf-8", newline="\\n") as stream:
                for key, value in contract["environment"].items():
                    stream.write(f"{key}={value}\\n")
            os.chmod(env_file, 0o600)

            if "," in str(workspace) or "," in str(env_file):
                raise ReproductionRunnerError("docker_mount_path_contains_comma")

            uid_gid = f"{os.getuid()}:{os.getgid()}"
            tmpfs_bytes = min(
                contract["limits"]["memory_mb"] * 1024 * 1024 // 4,
                256 * 1024 * 1024,
            )
            run_args = [
                "run", "-d",
                "--name", container_name,
                "--pull=never",
                "--network=none",
                "--ipc=none",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--pids-limit", str(contract["limits"]["max_processes"]),
                "--memory", f'{contract["limits"]["memory_mb"]}m',
                "--cpus", str(contract["limits"]["cpu_cores"]),
                "--ulimit", "core=0:0",
                "--user", uid_gid,
                "--log-driver=none",
                "--mount", f"type=bind,src={workspace},dst=/workspace,readonly",
                "--tmpfs", f'/output:rw,nosuid,nodev,size={contract["limits"]["max_output_bytes"]}',
                "--tmpfs", f"/tmp:rw,nosuid,nodev,size={tmpfs_bytes}",
                "--env-file", str(env_file),
                "--workdir", "/workspace" if contract["working_directory"] == "." else (
                    "/workspace/" + contract["working_directory"]
                ),
                "--entrypoint", contract["command"][0],
                contract["toolchain"]["image_ref"],
                *contract["command"][1:],
            ]
            docker_env = {
                "PATH": f'{Path(docker_path).parent}:/usr/bin:/bin',
                "LANG": "C",
                "LC_ALL": "C",
            }

            try:
                started = _docker_call(
                    docker_path, run_args, timeout=DOCKER_START_TIMEOUT_SECONDS, env=docker_env
                )
            except subprocess.TimeoutExpired:
                cleanup_status = _remove_container(docker_path, container_name, docker_env)
                return {
                    "status": "NOT_RUN" if cleanup_status == "REMOVED" else "INCOMPLETE",
                    "reason": "docker_start_timeout",
                    "contract_sha256": contract_digest,
                    "container_cleanup": cleanup_status,
                }
            except OSError:
                return {
                    "status": "NOT_RUN",
                    "reason": "docker_start_failed",
                    "contract_sha256": contract_digest,
                }

            if started.returncode != 0 or not started.stdout.strip():
                cleanup_status = _remove_container(docker_path, container_name, docker_env)
                return {
                    "status": "NOT_RUN" if cleanup_status != "FAILED" else "INCOMPLETE",
                    "reason": "docker_container_start_failed",
                    "detail": (started.stderr or "")[:1024],
                    "contract_sha256": contract_digest,
                    "container_cleanup": cleanup_status,
                }

            try:
                waited = _docker_call(
                    docker_path, ["wait", container_name],
                    timeout=contract["limits"]["timeout_seconds"] + 5, env=docker_env,
                )
                if waited.returncode != 0 or not waited.stdout.strip().isdigit():
                    execution_error = "docker_wait_result_invalid"
                else:
                    exit_code = int(waited.stdout.strip())
            except subprocess.TimeoutExpired:
                timed_out = True
                _stop_container(docker_path, container_name, docker_env)
            except OSError:
                execution_error = "docker_wait_failed"

            try:
                copied = _docker_call(
                    docker_path, ["cp", f"{container_name}:/output/.", str(output_root)],
                    timeout=OUTPUT_COPY_TIMEOUT_SECONDS, env=docker_env,
                )
                if copied.returncode == 0:
                    output_result = _verify_outputs(
                        output_root,
                        contract["expected_outputs"],
                        contract["limits"]["max_output_bytes"],
                    )
                else:
                    output_result = {
                        "status": "FAIL",
                        "error": "container_output_copy_failed",
                        "detail": (copied.stderr or "")[:1024],
                    }
            except subprocess.TimeoutExpired:
                output_result = {"status": "FAIL", "error": "container_output_copy_timeout"}
            except OSError:
                output_result = {"status": "FAIL", "error": "container_output_copy_failed"}
            finally:
                cleanup_status = _remove_container(docker_path, container_name, docker_env)
    except (OSError, shutil.Error, ReproductionRunnerError) as exc:
        return {
            "status": "INCOMPLETE",
            "reason": str(exc) or type(exc).__name__,
            "contract_sha256": contract_digest,
            "container_cleanup": cleanup_status,
        }

    if cleanup_status != "REMOVED":
        status, reason = "INCOMPLETE", "container_cleanup_failed"
    elif timed_out:
        status, reason = "TIMED_OUT", "reproduction_timeout"
    elif execution_error:
        status, reason = "INCOMPLETE", execution_error
    elif output_result is None or output_result.get("status") != "PASS":
        status = "FAILED"
        reason = (output_result or {}).get("error", "output_validation_failed")
    elif exit_code != contract["expected_exit_code"]:
        status, reason = "FAILED", "unexpected_exit_code"
    else:
        status, reason = "SUCCEEDED", None

    return {
        "status": status,
        "reason": reason,
        "contract_sha256": contract_digest,
        "exit_code": exit_code,
        "expected_exit_code": contract["expected_exit_code"],
        "output_validation": output_result,
        "container_cleanup": cleanup_status,
        "network_access": "disabled",
        "finding_verdict": "UNCHANGED",
    }
