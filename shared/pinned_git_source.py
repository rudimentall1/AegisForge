"""Read Solidity source bytes from an exact, origin-verified Git commit.

The loader is deliberately read-only. It does not execute repository code and
never trusts mutable working-tree contents for the source passed to an adapter.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit


class PinnedSourceError(ValueError):
    """A requested source cannot be proven to belong to the pinned repository commit."""


_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_MAX_SOURCE_FILES = 500
_MAX_SOURCE_BYTES = 4 * 1024 * 1024


def _git(root: Path, args: list[str], *, timeout: int = 10) -> bytes:
    git = os.environ.get("GIT_EXECUTABLE", "git")
    env = {
        "PATH": os.pathsep.join(
            [str(Path(git).parent), "/usr/bin", "/bin"]
        ),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "LANG": "C",
        "LC_ALL": "C",
    }
    try:
        completed = subprocess.run(
            [git, "-C", str(root), *args],
            capture_output=True,
            text=False,
            timeout=timeout,
            check=False,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PinnedSourceError("target_git_command_failed") from exc
    if completed.returncode != 0:
        raise PinnedSourceError("target_git_command_failed")
    return completed.stdout


def _normalized_origin(value: str) -> str:
    value = value.strip()
    if value.startswith("git@github.com:"):
        path = value[len("git@github.com:"):]
    else:
        try:
            parsed = urlsplit(value)
        except ValueError as exc:
            raise PinnedSourceError("target_git_origin_mismatch") from exc
        if (
            parsed.scheme not in {"https", "ssh"}
            or parsed.hostname != "github.com"
            or parsed.username not in {None, "git"}
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise PinnedSourceError("target_git_origin_mismatch")
        path = parsed.path.lstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
    return path.lower()


def _validate_source_path(path: object) -> str:
    if (
        not isinstance(path, str)
        or not path
        or len(path) > 1024
        or "\x00" in path
        or "\\" in path
    ):
        raise PinnedSourceError("source_path_invalid")
    parts = path.split("/")
    if (
        path.startswith("/")
        or any(part in {"", ".", ".."} for part in parts)
        or ":" in parts[0]
        or not path.lower().endswith(".sol")
        or any(ord(char) < 32 for char in path)
    ):
        raise PinnedSourceError("source_path_invalid")
    return path


def load_pinned_solidity_sources(
    checkout_root: str | Path,
    *,
    repository: str,
    commit_sha: str,
    source_paths: list[str] | tuple[str, ...],
    max_files: int = _MAX_SOURCE_FILES,
    max_bytes: int = _MAX_SOURCE_BYTES,
) -> dict:
    """Load UTF-8 Solidity blobs from the exact commit after verifying Git identity.

    Git's object database is the source of truth: dirty or replaced working-tree
    files do not affect returned source text. Symlink and non-blob tree entries
    are rejected. The caller remains responsible for authorizing source_paths
    against the ResearchCase scope before invoking this function.
    """
    if not isinstance(repository, str) or not _REPOSITORY_RE.fullmatch(repository):
        raise PinnedSourceError("target_repository_invalid")
    if not isinstance(commit_sha, str) or not _COMMIT_RE.fullmatch(commit_sha):
        raise PinnedSourceError("target_commit_sha_invalid")
    if not isinstance(source_paths, (list, tuple)) or not source_paths:
        raise PinnedSourceError("source_paths_required")
    if (
        isinstance(max_files, bool)
        or not isinstance(max_files, int)
        or not 1 <= max_files <= _MAX_SOURCE_FILES
    ):
        raise PinnedSourceError("source_file_limit_invalid")
    if len(source_paths) > max_files:
        raise PinnedSourceError("source_file_count_exceeded")
    if (
        isinstance(max_bytes, bool) or not isinstance(max_bytes, int)
        or max_bytes < 1 or max_bytes > _MAX_SOURCE_BYTES
    ):
        raise PinnedSourceError("source_byte_limit_invalid")

    normalized_paths = [_validate_source_path(path) for path in source_paths]
    if len(set(normalized_paths)) != len(normalized_paths):
        raise PinnedSourceError("source_path_duplicate")

    raw_root = Path(checkout_root)
    if raw_root.is_symlink():
        raise PinnedSourceError("target_git_checkout_required")
    try:
        root = raw_root.resolve(strict=True)
    except (OSError, ValueError) as exc:
        raise PinnedSourceError("target_git_checkout_required") from exc
    git_dir = root / ".git"
    if git_dir.is_symlink() or not git_dir.is_dir():
        raise PinnedSourceError("target_git_checkout_required")

    revision = _git(root, ["rev-parse", "--verify", "HEAD"]).decode("ascii", "strict").strip()
    if not _COMMIT_RE.fullmatch(revision):
        raise PinnedSourceError("target_git_revision_unavailable")
    if revision != commit_sha:
        raise PinnedSourceError("target_git_revision_mismatch")

    origin = _git(root, ["remote", "get-url", "origin"]).decode("utf-8", "strict").strip()
    if _normalized_origin(origin) != repository.lower():
        raise PinnedSourceError("target_git_origin_mismatch")

    sources: dict[str, str] = {}
    source_digests: dict[str, str] = {}
    total_bytes = 0
    for relative in normalized_paths:
        entry = _git(root, ["ls-tree", "-z", commit_sha, "--", relative])
        records = [item for item in entry.split(b"\x00") if item]
        if len(records) != 1:
            raise PinnedSourceError("target_source_file_missing")
        try:
            metadata, returned_path = records[0].split(b"\t", 1)
            mode, object_type, object_id = metadata.split(b" ", 2)
        except ValueError as exc:
            raise PinnedSourceError("target_git_tree_entry_invalid") from exc
        if returned_path.decode("utf-8", "strict") != relative:
            raise PinnedSourceError("target_git_tree_path_mismatch")
        if mode == b"120000":
            raise PinnedSourceError("target_source_symlink_rejected")
        if mode not in {b"100644", b"100755"} or object_type != b"blob":
            raise PinnedSourceError("target_source_not_regular_blob")
        if not re.fullmatch(rb"[0-9a-f]{40}", object_id):
            raise PinnedSourceError("target_git_object_id_invalid")

        size_output = _git(root, ["cat-file", "-s", object_id.decode("ascii")])
        try:
            blob_size = int(size_output.decode("ascii", "strict").strip())
        except (UnicodeDecodeError, ValueError) as exc:
            raise PinnedSourceError("target_git_blob_size_invalid") from exc
        if blob_size < 0 or total_bytes + blob_size > max_bytes:
            raise PinnedSourceError("source_bytes_exceeded")
        blob = _git(root, ["cat-file", "blob", object_id.decode("ascii")])
        if len(blob) != blob_size:
            raise PinnedSourceError("target_git_blob_size_mismatch")
        total_bytes += blob_size
        try:
            source = blob.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise PinnedSourceError("target_source_invalid_utf8") from exc
        sources[relative] = source
        source_digests[relative] = hashlib.sha256(blob).hexdigest()

    tree_payload = json.dumps(
        source_digests, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        "repository": repository,
        "target_commit": commit_sha,
        "sources": sources,
        "source_sha256": source_digests,
        "source_tree_sha256": hashlib.sha256(tree_payload).hexdigest(),
        "source_count": len(sources),
        "source_bytes": total_bytes,
        "source_provenance": "git_object_database_at_verified_commit",
    }
