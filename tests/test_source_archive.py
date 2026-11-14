import io
import tarfile

import pytest

from shared.source_archive import (
    SourceArchiveError,
    SourceArchiveLimits,
    extract_github_source_archive,
)


def make_archive(entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, kind, payload in entries:
            info = tarfile.TarInfo(name)
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif kind == "file":
                data = payload if isinstance(payload, bytes) else payload.encode()
                info.size = len(data)
                if name.endswith(".sh"):
                    info.mode = 0o755
                archive.addfile(info, io.BytesIO(data))
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = payload
                archive.addfile(info)
            elif kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = payload
                archive.addfile(info)
            else:
                raise AssertionError(kind)
    return buffer.getvalue()


def test_extracts_regular_files_without_preserving_archive_permissions(tmp_path):
    archive = make_archive([
        ("repo-commit/", "dir", b""),
        ("repo-commit/contracts/", "dir", b""),
        ("repo-commit/contracts/Vault.sol", "file", "contract Vault {}"),
        ("repo-commit/run.sh", "file", b"#!/bin/sh\necho unsafe"),
    ])
    destination = tmp_path / "source"
    result = extract_github_source_archive(archive, destination)

    assert result.root == destination / "repo-commit"
    assert result.file_count == 2
    assert result.total_bytes == len("contract Vault {}") + len(b"#!/bin/sh\necho unsafe")
    assert (result.root / "contracts/Vault.sol").read_text() == "contract Vault {}"
    assert (result.root / "run.sh").stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize(
    "entries",
    [
        [("../escape", "file", "x")],
        [("/absolute", "file", "x")],
        [("root/..\\escape", "file", "x")],
        [("root/a", "file", "x"), ("root/a", "file", "y")],
        [("root/a", "file", "x"), ("other/b", "file", "y")],
        [("root/link", "symlink", "../../etc/passwd")],
        [("root/link", "hardlink", "root/file")],
    ],
)
def test_rejects_unsafe_archive_members_before_writing(tmp_path, entries):
    archive = make_archive(entries)
    destination = tmp_path / "source"
    with pytest.raises(SourceArchiveError):
        extract_github_source_archive(archive, destination)
    assert not destination.exists()


def test_rejects_file_directory_collisions(tmp_path):
    archive = make_archive([
        ("root/a", "file", "x"),
        ("root/a/child", "file", "y"),
    ])
    with pytest.raises(SourceArchiveError, match="file_directory_collision"):
        extract_github_source_archive(archive, tmp_path / "source")


def test_rejects_file_as_parent_of_explicit_directory(tmp_path):
    archive = make_archive([
        ("root/a", "file", "x"),
        ("root/a/child/", "dir", b""),
    ])
    with pytest.raises(SourceArchiveError, match="file_directory_collision"):
        extract_github_source_archive(archive, tmp_path / "source")


def test_enforces_compressed_and_uncompressed_budgets(tmp_path):
    archive = make_archive([("root/large.bin", "file", b"x" * 4096)])
    with pytest.raises(SourceArchiveError, match="compressed_size"):
        extract_github_source_archive(
            archive,
            tmp_path / "compressed",
            limits=SourceArchiveLimits(max_archive_bytes=1),
        )
    with pytest.raises(SourceArchiveError, match="uncompressed_size"):
        extract_github_source_archive(
            archive,
            tmp_path / "expanded",
            limits=SourceArchiveLimits(max_uncompressed_bytes=100),
        )


def test_rejects_existing_destination(tmp_path):
    destination = tmp_path / "source"
    destination.mkdir()
    archive = make_archive([("root/file", "file", "x")])
    with pytest.raises(SourceArchiveError, match="destination_must_not_exist"):
        extract_github_source_archive(archive, destination)
