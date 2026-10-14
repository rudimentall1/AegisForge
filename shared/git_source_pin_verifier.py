"""Verify a pinned source file against local Git objects.

This helper performs no network access. It proves that the supplied local Git
object database resolves a file at an exact commit to the expected blob bytes.
It does not authenticate the repository owner or establish independent provenance.
"""
import hashlib
import os
import re
import subprocess
from pathlib import Path


class GitSourcePinError(ValueError):
    """Raised when a local Git object does not match the requested source pin."""


_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")


def _git(repo_path, *args):
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), *args],
            check=False,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitSourcePinError("git_command_failed") from exc
    if result.returncode != 0:
        raise GitSourcePinError("git_object_unavailable")
    return result.stdout


def verify_git_source_pin(
    repo_path,
    *,
    expected_repository,
    expected_commit_sha,
    expected_path,
    expected_blob_sha,
):
    """Verify exact commit and file blob in a local Git repository.

    The repository name is a declared coordinate, not an authenticated identity.
    The result intentionally keeps provenance_verified false.
    """
    if not isinstance(expected_repository, str) or not expected_repository.strip():
        raise GitSourcePinError("expected_repository_required")
    if not isinstance(expected_commit_sha, str) or not _SHA1_RE.fullmatch(expected_commit_sha):
        raise GitSourcePinError("expected_commit_sha_invalid")
    if not isinstance(expected_blob_sha, str) or not _SHA1_RE.fullmatch(expected_blob_sha):
        raise GitSourcePinError("expected_blob_sha_invalid")
    if not isinstance(expected_path, str) or not expected_path:
        raise GitSourcePinError("expected_path_required")

    path = Path(expected_path)
    if (
        path.is_absolute()
        or any(part in ("", ".", "..") for part in expected_path.split("/"))
        or "\\" in expected_path
        or any(ord(char) < 32 or ord(char) == 127 for char in expected_path)
    ):
        raise GitSourcePinError("expected_path_invalid")

    commit = _git(repo_path, "rev-parse", "--verify", f"{expected_commit_sha}^{{commit}}").decode("ascii").strip()
    if commit != expected_commit_sha:
        raise GitSourcePinError("commit_sha_mismatch")

    tree_output = _git(
        repo_path,
        "ls-tree",
        "-z",
        "--full-tree",
        commit,
        "--",
        f":(literal){expected_path}",
    )
    records = [record for record in tree_output.split(b"\0") if record]
    if len(records) != 1 or b"\\t" not in records[0]:
        raise GitSourcePinError("git_path_not_single_file")
    header, actual_path = records[0].split(b"\t", 1)
    fields = header.split(b" ")
    if len(fields) != 3 or actual_path != os.fsencode(expected_path):
        raise GitSourcePinError("git_path_entry_mismatch")
    mode, object_type, blob_bytes = fields
    if mode not in (b"100644", b"100755") or object_type != b"blob":
        raise GitSourcePinError("git_path_not_regular_file")
    try:
        blob_sha = blob_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise GitSourcePinError("git_blob_sha_invalid") from exc
    if not _SHA1_RE.fullmatch(blob_sha):
        raise GitSourcePinError("git_blob_sha_invalid")
    if blob_sha != expected_blob_sha:
        raise GitSourcePinError("git_blob_sha_mismatch")

    content = _git(repo_path, "cat-file", "blob", blob_sha)
    actual_blob_sha = hashlib.sha1(
        b"blob " + str(len(content)).encode("ascii") + b"\0" + content
    ).hexdigest()
    if actual_blob_sha != blob_sha:
        raise GitSourcePinError("git_blob_content_mismatch")

    return {
        "valid": True,
        "repository": expected_repository,
        "commit_sha": commit,
        "path": expected_path,
        "git_blob_sha": actual_blob_sha,
        "git_object_match": True,
        "provenance_verified": False,
    }
