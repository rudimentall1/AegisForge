"""Bounded, non-executing extraction of pinned-source GitHub tar archives.

The caller must resolve the requested full commit SHA and Git tree through
GitHub's API before fetching an archive for that SHA. This module validates
archive structure and writes only regular files/directories; it does not
perform network access or execute repository content.
"""
from __future__ import annotations

import hashlib
import io
import os
import stat
import shutil
import tarfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class PinnedCommit:
    commit_sha: str
    tree_sha: str


class SourceArchiveError(ValueError):
    """A source archive violates the bounded extraction contract."""


@dataclass(frozen=True, slots=True)
class SourceArchiveLimits:
    max_archive_bytes: int = 64 * 1024 * 1024
    max_uncompressed_bytes: int = 256 * 1024 * 1024
    max_files: int = 20_000


@dataclass(frozen=True, slots=True)
class ExtractedSource:
    root: Path
    file_count: int
    total_bytes: int


def _safe_member_parts(name: str) -> tuple[str, ...]:
    if not isinstance(name, str) or not name or "\x00" in name or "\\" in name:
        raise SourceArchiveError("archive_member_name_invalid")
    if name.startswith("/"):
        raise SourceArchiveError("archive_absolute_path_rejected")
    trimmed = name[:-1] if name.endswith("/") else name
    parts = tuple(trimmed.split("/"))
    if (
        not parts
        or any(part in {"", ".", ".."} for part in parts)
        or ":" in parts[0]
    ):
        raise SourceArchiveError("archive_path_traversal_rejected")
    return parts


def extract_github_source_archive(
    archive_bytes: bytes,
    destination: str | os.PathLike[str],
    *,
    limits: SourceArchiveLimits = SourceArchiveLimits(),
) -> ExtractedSource:
    """Safely extract a previously resolved GitHub commit tarball.

    Destination must not exist. Archive ownership, timestamps, and permission
    bits are not trusted or preserved. Symlinks, hardlinks, devices, FIFOs,
    sparse entries, duplicate paths, and multiple archive roots are rejected.
    """
    if not isinstance(archive_bytes, bytes):
        raise SourceArchiveError("archive_bytes_required")
    if (
        limits.max_archive_bytes <= 0
        or limits.max_uncompressed_bytes <= 0
        or limits.max_files <= 0
    ):
        raise SourceArchiveError("archive_limits_invalid")
    if len(archive_bytes) == 0 or len(archive_bytes) > limits.max_archive_bytes:
        raise SourceArchiveError("archive_compressed_size_out_of_bounds")

    target = Path(destination)
    if target.exists():
        raise SourceArchiveError("destination_must_not_exist")

    target_created = False
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            members = archive.getmembers()
            if not members or len(members) > (limits.max_files * 2) + 1:
                raise SourceArchiveError("archive_member_count_out_of_bounds")

            root_name: str | None = None
            explicit_paths: set[tuple[str, ...]] = set()
            file_paths: set[tuple[str, ...]] = set()
            all_paths: set[tuple[str, ...]] = set()
            directory_paths: set[tuple[str, ...]] = set()
            total_bytes = 0
            regular_files = 0
            validated: list[tuple[tarfile.TarInfo, tuple[str, ...]]] = []

            for member in members:
                parts = _safe_member_parts(member.name)
                if root_name is None:
                    root_name = parts[0]
                if parts[0] != root_name:
                    raise SourceArchiveError("archive_multiple_roots_rejected")
                if parts in explicit_paths:
                    raise SourceArchiveError("archive_duplicate_path_rejected")
                explicit_paths.add(parts)
                all_paths.add(parts)

                if member.isdir():
                    directory_paths.add(parts)
                    continue
                if not member.isfile() or member.issparse():
                    raise SourceArchiveError("archive_non_regular_member_rejected")
                if len(parts) == 1:
                    raise SourceArchiveError("archive_root_file_rejected")

                regular_files += 1
                if regular_files > limits.max_files:
                    raise SourceArchiveError("archive_file_count_out_of_bounds")
                if member.size < 0:
                    raise SourceArchiveError("archive_file_size_invalid")
                total_bytes += member.size
                if total_bytes > limits.max_uncompressed_bytes:
                    raise SourceArchiveError("archive_uncompressed_size_out_of_bounds")
                file_paths.add(parts)
                validated.append((member, parts))

            for path_parts in all_paths:
                for index in range(1, len(path_parts)):
                    if path_parts[:index] in file_paths:
                        raise SourceArchiveError("archive_file_directory_collision")

            target.mkdir(parents=False, exist_ok=False)
            target_created = True
            root_dir = target / root_name
            root_dir.mkdir()

            for directory in sorted(directory_paths, key=lambda p: (len(p), p)):
                if len(directory) == 1:
                    continue
                (target.joinpath(*directory)).mkdir(parents=True, exist_ok=True)

            for member, parts in validated:
                output = target.joinpath(*parts)
                output.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise SourceArchiveError("archive_file_payload_missing")
                remaining = member.size
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                fd = os.open(output, flags, 0o600)
                try:
                    with os.fdopen(fd, "wb") as sink, source:
                        while remaining:
                            chunk = source.read(min(1024 * 1024, remaining))
                            if not chunk:
                                raise SourceArchiveError("archive_file_payload_truncated")
                            sink.write(chunk)
                            remaining -= len(chunk)
                        if source.read(1):
                            raise SourceArchiveError("archive_file_payload_size_mismatch")
                except Exception:
                    try:
                        os.unlink(output)
                    except FileNotFoundError:
                        pass
                    raise
                executable = bool(member.mode & 0o111)
                os.chmod(output, 0o700 if executable else 0o600)

            return ExtractedSource(
                root=root_dir,
                file_count=regular_files,
                total_bytes=total_bytes,
            )
    except SourceArchiveError:
        if target_created:
            shutil.rmtree(target, ignore_errors=True)
        raise
    except (tarfile.TarError, OSError, EOFError) as exc:
        if target_created:
            shutil.rmtree(target, ignore_errors=True)
        raise SourceArchiveError("archive_invalid_or_unreadable") from exc
    except Exception:
        if target_created:
            shutil.rmtree(target, ignore_errors=True)
        raise



def validate_pinned_commit_metadata(
    expected_commit_sha: str,
    metadata: object,
) -> PinnedCommit:
    """Validate a GitHub commit API response against a full requested SHA."""
    if (
        not isinstance(expected_commit_sha, str)
        or len(expected_commit_sha) != 40
        or any(ch not in "0123456789abcdefABCDEF" for ch in expected_commit_sha)
    ):
        raise SourceArchiveError("full_commit_sha_required")
    if not isinstance(metadata, dict):
        raise SourceArchiveError("commit_metadata_invalid")
    actual_sha = metadata.get("sha")
    commit = metadata.get("commit")
    tree = commit.get("tree") if isinstance(commit, dict) else None
    tree_sha = tree.get("sha") if isinstance(tree, dict) else None
    if not isinstance(actual_sha, str) or actual_sha.lower() != expected_commit_sha.lower():
        raise SourceArchiveError("resolved_commit_sha_mismatch")
    if (
        not isinstance(tree_sha, str)
        or len(tree_sha) != 40
        or any(ch not in "0123456789abcdefABCDEF" for ch in tree_sha)
    ):
        raise SourceArchiveError("resolved_tree_sha_invalid")
    return PinnedCommit(actual_sha.lower(), tree_sha.lower())


def compute_git_tree_sha(root: str | os.PathLike[str]) -> str:
    """Compute the Git SHA-1 tree object ID for a regular-file-only checkout.

    Git symlinks and gitlinks/submodules are intentionally unsupported. Empty
    directories are ignored, as they are not represented in Git trees.
    """
    root_path = Path(root)
    if not root_path.is_dir() or root_path.is_symlink():
        raise SourceArchiveError("source_root_invalid")

    def build(directory: Path) -> bytes:
        entries: list[tuple[bytes, bytes, bytes]] = []
        try:
            children = list(directory.iterdir())
        except OSError as exc:
            raise SourceArchiveError("source_tree_unreadable") from exc

        for child in children:
            name = child.name
            try:
                name_bytes = os.fsencode(name)
            except (UnicodeError, ValueError) as exc:
                raise SourceArchiveError("source_filename_invalid") from exc
            if not name_bytes or b"/" in name_bytes or b"\\x00" in name_bytes:
                raise SourceArchiveError("source_filename_invalid")
            try:
                mode = child.lstat().st_mode
            except OSError as exc:
                raise SourceArchiveError("source_tree_unreadable") from exc

            if stat.S_ISDIR(mode):
                child_tree = build(child)
                if not child_tree:
                    continue
                object_sha = hashlib.sha1(b"tree " + str(len(child_tree)).encode() + b"\0" + child_tree).digest()
                entries.append((name_bytes + b"/", b"40000", object_sha))
            elif stat.S_ISREG(mode):
                try:
                    data = child.read_bytes()
                except OSError as exc:
                    raise SourceArchiveError("source_file_unreadable") from exc
                blob_header = b"blob " + str(len(data)).encode() + b"\0"
                object_sha = hashlib.sha1(blob_header + data).digest()
                file_mode = b"100755" if mode & 0o111 else b"100644"
                entries.append((name_bytes, file_mode, object_sha))
            else:
                raise SourceArchiveError("source_non_regular_entry_rejected")

        entries.sort(key=lambda item: item[0])
        payload = b"".join(
            mode + b" " + sort_name.rstrip(b"/") + b"\0" + object_sha
            for sort_name, mode, object_sha in entries
        )
        header = b"tree " + str(len(payload)).encode() + b"\0"
        return header + payload

    root_object = build(root_path)
    return hashlib.sha1(root_object).hexdigest()



def verify_extracted_source_tree(
    extracted: ExtractedSource,
    pinned_commit: PinnedCommit,
) -> str:
    """Fail closed unless extracted regular files reproduce the pinned Git tree."""
    if not isinstance(extracted, ExtractedSource) or not isinstance(pinned_commit, PinnedCommit):
        raise SourceArchiveError("source_verification_inputs_invalid")
    actual_tree_sha = compute_git_tree_sha(extracted.root)
    if actual_tree_sha != pinned_commit.tree_sha:
        raise SourceArchiveError("extracted_git_tree_sha_mismatch")
    return actual_tree_sha



def extract_and_verify_pinned_github_source_archive(
    archive_bytes: bytes,
    destination: str | os.PathLike[str],
    *,
    expected_commit_sha: str,
    commit_metadata: object,
    limits: SourceArchiveLimits = SourceArchiveLimits(),
) -> tuple[ExtractedSource, PinnedCommit]:
    """Extract only when commit metadata and resulting Git tree both match."""
    pinned = validate_pinned_commit_metadata(expected_commit_sha, commit_metadata)
    extracted = extract_github_source_archive(
        archive_bytes,
        destination,
        limits=limits,
    )
    try:
        verify_extracted_source_tree(extracted, pinned)
    except Exception:
        shutil.rmtree(Path(destination), ignore_errors=True)
        raise
    return extracted, pinned
