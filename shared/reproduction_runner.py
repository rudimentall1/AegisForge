"""Explicitly invoked, network-disabled Docker runner for reproduction contracts.

This module never runs bundle commands on the host. It requires a locally
available, digest-pinned image and runs with no network, no capabilities,
read-only container root, bounded resources, and a size-limited output tmpfs.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from shared.reproduction_contract import (
    ReproductionContractError,
    contract_sha256,
    validate_reproduction_contract,
)

MAX_WORKSPACE_FILES = 100_000
MAX_WORKSPACE_BYTES = 1024 * 1024 * 1024
MAX_GIT_TREE_OUTPUT_BYTES = 32 * 1024 * 1024
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


def _git_environment(git_path: str) -> dict[str, str]:
    return {
        "PATH": f"{Path(git_path).parent}:/usr/bin:/bin",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "LANG": "C",
        "LC_ALL": "C",
    }


def _verify_git_target(root: Path, target: dict) -> tuple[str, dict[str, str]]:
    git_directory = root / ".git"
    if git_directory.is_symlink() or not git_directory.is_dir():
        raise ReproductionRunnerError("target_git_checkout_required")
    git_path = shutil.which("git")
    if not git_path:
        raise ReproductionRunnerError("git_binary_not_available")
    git_env = _git_environment(git_path)
    try:
        revision = subprocess.run(
            [git_path, "-C", str(root), "rev-parse", "--verify", "HEAD"],
            capture_output=True, text=True, timeout=5, check=False, env=git_env,
        )
        remote = subprocess.run(
            [git_path, "-C", str(root), "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=5, check=False, env=git_env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReproductionRunnerError("target_git_identity_check_failed") from exc
    if revision.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}\s*", revision.stdout or ""):
        raise ReproductionRunnerError("target_git_revision_unavailable")
    if revision.stdout.strip() != target["commit_sha"]:
        raise ReproductionRunnerError("target_git_revision_mismatch")
    if remote.returncode != 0:
        raise ReproductionRunnerError("target_git_origin_unavailable")
    remote_value = (remote.stdout or "").strip()
    if remote_value.startswith("git@github.com:"):
        remote_path = remote_value[len("git@github.com:"):]
    else:
        try:
            parsed = urlsplit(remote_value)
            if parsed.scheme not in ("https", "ssh") or parsed.hostname != "github.com":
                raise ReproductionRunnerError("target_git_origin_mismatch")
            if parsed.username not in (None, "git") or parsed.password is not None:
                raise ReproductionRunnerError("target_git_origin_credentials_rejected")
            remote_path = parsed.path.lstrip("/")
        except ValueError as exc:
            raise ReproductionRunnerError("target_git_origin_mismatch") from exc
    if remote_path.endswith(".git"):
        remote_path = remote_path[:-4]
    if remote_path.lower() != target["repository"].lower():
        raise ReproductionRunnerError("target_git_origin_mismatch")
    return git_path, git_env


def _copy_pinned_worktree(
    root: Path,
    target: dict,
    destination: Path,
    git_path: str,
    git_env: dict[str, str],
) -> tuple[int, int]:
    try:
        tree = subprocess.run(
            [git_path, "-C", str(root), "ls-tree", "-r", "-z", "--full-tree", "HEAD"],
            capture_output=True, text=False, timeout=30, check=False, env=git_env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReproductionRunnerError("target_git_tree_read_failed") from exc
    if tree.returncode != 0:
        raise ReproductionRunnerError("target_git_tree_read_failed")
    if len(tree.stdout) > MAX_GIT_TREE_OUTPUT_BYTES:
        raise ReproductionRunnerError("target_git_tree_output_limit_exceeded")

    entries = [entry for entry in tree.stdout.split(b"\x00") if entry]
    if not entries:
        raise ReproductionRunnerError("target_git_tree_empty")
    if len(entries) > MAX_WORKSPACE_FILES:
        raise ReproductionRunnerError("workspace_file_count_limit_exceeded")

    total_bytes = 0
    copied_files = 0
    for entry in entries:
        try:
            metadata, raw_path = entry.split(b"\t", 1)
            mode, object_type, object_id = metadata.split(b" ", 2)
            relative = os.fsdecode(raw_path)
        except (ValueError, UnicodeError) as exc:
            raise ReproductionRunnerError("target_git_tree_entry_invalid") from exc
        parts = relative.split("/")
        if (
            not relative
            or relative.startswith("/")
            or "\\" in relative
            or any(part in ("", ".", "..", ".git") for part in parts)
            or ":" in parts[0]
            or any(ord(char) < 32 for char in relative)
        ):
            raise ReproductionRunnerError("target_git_tree_path_invalid")
        if mode == b"120000":
            raise ReproductionRunnerError("workspace_symlink_rejected")
        if mode not in (b"100644", b"100755") or object_type != b"blob":
            raise ReproductionRunnerError("target_git_tree_non_regular_file_rejected")
        if not re.fullmatch(rb"[0-9a-f]{40}", object_id):
            raise ReproductionRunnerError("target_git_tree_object_id_invalid")

        source = root.joinpath(*parts)
        source_cursor = root
        for part in parts:
            source_cursor = source_cursor / part
            if source_cursor.is_symlink():
                raise ReproductionRunnerError("workspace_symlink_rejected")
        try:
            source_resolved = source.resolve(strict=True)
            source_resolved.relative_to(root)
            file_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except (OSError, ValueError) as exc:
            raise ReproductionRunnerError(f"target_worktree_file_unavailable:{relative}") from exc

        target_path = destination.joinpath(*parts)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha1()
        with os.fdopen(file_fd, "rb") as input_stream:
            source_stat = os.fstat(input_stream.fileno())
            if not stat.S_ISREG(source_stat.st_mode):
                raise ReproductionRunnerError("workspace_special_file_rejected")
            file_size = source_stat.st_size
            total_bytes += file_size
            if file_size > MAX_WORKSPACE_BYTES or total_bytes > MAX_WORKSPACE_BYTES:
                raise ReproductionRunnerError("workspace_size_limit_exceeded")
            digest.update(f"blob {file_size}\x00".encode("ascii"))
            actual_size = 0
            with target_path.open("xb") as output_stream:
                while True:
                    chunk = input_stream.read(1024 * 1024)
                    if not chunk:
                        break
                    actual_size += len(chunk)
                    if actual_size > file_size or actual_size > MAX_WORKSPACE_BYTES:
                        raise ReproductionRunnerError("target_worktree_file_changed_during_copy")
                    digest.update(chunk)
                    output_stream.write(chunk)
            if actual_size != file_size or digest.hexdigest().encode("ascii") != object_id:
                raise ReproductionRunnerError(f"target_worktree_file_mismatch:{relative}")
        target_path.chmod(0o755 if mode == b"100755" else 0o644)
        copied_files += 1
    return copied_files, total_bytes


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
    git_path, git_env = _verify_git_target(root, contract["target"])

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
            workspace.mkdir()
            _copy_pinned_worktree(root, contract["target"], workspace, git_path, git_env)
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
            with env_file.open("x", encoding="utf-8", newline="\n") as stream:
                for key, value in contract["environment"].items():
                    stream.write(f"{key}={value}\n")
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
