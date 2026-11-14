"""Bounded, non-executing extraction of pinned-source GitHub tar archives.

The caller must resolve the requested full commit SHA and Git tree through
GitHub's API before fetching an archive for that SHA. This module validates
archive structure and writes only regular files/directories; it does not
perform network access or execute repository content.
"""
from __future__ import annotations

import io
import os
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


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
    if len(archive_bytes) == 0 or len(archive_bytes) > limits.max_archive_bytes:
        raise SourceArchiveError("archive_compressed_size_out_of_bounds")
    if (
        limits.max_archive_bytes <= 0
        or limits.max_uncompressed_bytes <= 0
        or limits.max_files <= 0
    ):
        raise SourceArchiveError("archive_limits_invalid")

    target = Path(destination)
    if target.exists():
        raise SourceArchiveError("destination_must_not_exist")

    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            members = archive.getmembers()
            if not members or len(members) > limits.max_files + 1:
                raise SourceArchiveError("archive_member_count_out_of_bounds")

            root_name: str | None = None
            explicit_paths: set[tuple[str, ...]] = set()
            file_paths: set[tuple[str, ...]] = set()
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

            for file_path in file_paths:
                for index in range(1, len(file_path)):
                    parent = file_path[:index]
                    if parent in file_paths:
                        raise SourceArchiveError("archive_file_directory_collision")

            target.mkdir(parents=False, exist_ok=False)
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
        raise
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise SourceArchiveError("archive_invalid_or_unreadable") from exc
