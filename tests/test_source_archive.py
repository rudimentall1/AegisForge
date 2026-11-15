import gzip
import io
import tarfile

import pytest

from shared.source_archive import (
    SourceArchiveError,
    SourceArchiveLimits,
    extract_github_source_archive,
    compute_git_tree_sha,
    verify_extracted_source_tree,
    ExtractedSource,
    PinnedCommit,
    validate_pinned_commit_metadata,
    extract_and_verify_pinned_github_source_archive,
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



def test_validates_full_commit_sha_and_returns_tree_identity():
    commit_sha = "a" * 40
    tree_sha = "b" * 40
    result = validate_pinned_commit_metadata(
        commit_sha,
        {"sha": commit_sha, "commit": {"tree": {"sha": tree_sha}}},
    )
    assert result.commit_sha == commit_sha
    assert result.tree_sha == tree_sha


@pytest.mark.parametrize(
    "expected,metadata,error",
    [
        ("short", {"sha": "short", "commit": {"tree": {"sha": "b" * 40}}}, "full_commit_sha"),
        ("a" * 40, {"sha": "c" * 40, "commit": {"tree": {"sha": "b" * 40}}}, "commit_sha_mismatch"),
        ("a" * 40, {"sha": "a" * 40, "commit": {"tree": {"sha": "bad"}}}, "tree_sha_invalid"),
        ("a" * 40, None, "commit_metadata_invalid"),
    ],
)
def test_rejects_unpinned_or_malformed_commit_metadata(expected, metadata, error):
    with pytest.raises(SourceArchiveError, match=error):
        validate_pinned_commit_metadata(expected, metadata)


def test_computes_git_tree_sha_and_detects_content_or_mode_changes(tmp_path):
    root = tmp_path / "checkout"
    root.mkdir()
    (root / "README.md").write_bytes(b"hello\n")
    nested = root / "src"
    nested.mkdir()
    script = nested / "run.sh"
    script.write_bytes(b"#!/bin/sh\n")
    script.chmod(0o700)

    original = compute_git_tree_sha(root)
    assert len(original) == 40

    script.write_bytes(b"#!/bin/sh\necho changed\n")
    assert compute_git_tree_sha(root) != original

    script.write_bytes(b"#!/bin/sh\n")
    script.chmod(0o600)
    assert compute_git_tree_sha(root) != original


def test_git_tree_sha_rejects_symlinks(tmp_path):
    root = tmp_path / "checkout"
    root.mkdir()
    (root / "link").symlink_to(tmp_path / "outside")
    with pytest.raises(SourceArchiveError, match="non_regular_entry"):
        compute_git_tree_sha(root)


def test_git_tree_sha_ignores_empty_directories(tmp_path):
    root = tmp_path / "checkout"
    root.mkdir()
    baseline = compute_git_tree_sha(root)
    assert baseline == "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
    (root / "empty").mkdir()
    assert compute_git_tree_sha(root) == baseline



def test_extracted_source_must_match_pinned_tree_sha(tmp_path):
    archive = make_archive([("repo/file.txt", "file", "pinned content")])
    extracted = extract_github_source_archive(archive, tmp_path / "source")
    tree_sha = compute_git_tree_sha(extracted.root)
    pinned = PinnedCommit("a" * 40, tree_sha)
    assert verify_extracted_source_tree(extracted, pinned) == tree_sha

    tampered = extracted.root / "file.txt"
    tampered.write_text("modified")
    with pytest.raises(SourceArchiveError, match="git_tree_sha_mismatch"):
        verify_extracted_source_tree(extracted, pinned)


def test_tree_verification_rejects_untrusted_input_types():
    with pytest.raises(SourceArchiveError, match="inputs_invalid"):
        verify_extracted_source_tree(object(), object())



def test_combined_pinned_extraction_requires_matching_commit_and_tree(tmp_path):
    archive = make_archive([("repo/file.txt", "file", "pinned content")])
    probe = extract_github_source_archive(archive, tmp_path / "probe")
    expected_tree = compute_git_tree_sha(probe.root)
    import shutil
    shutil.rmtree(tmp_path / "probe")

    commit_sha = "a" * 40
    metadata = {"sha": commit_sha, "commit": {"tree": {"sha": expected_tree}}}
    extracted, pinned = extract_and_verify_pinned_github_source_archive(
        archive,
        tmp_path / "verified",
        expected_commit_sha=commit_sha,
        commit_metadata=metadata,
    )
    assert extracted.root.joinpath("file.txt").read_text() == "pinned content"
    assert pinned.tree_sha == expected_tree

    with pytest.raises(SourceArchiveError, match="git_tree_sha_mismatch"):
        extract_and_verify_pinned_github_source_archive(
            archive,
            tmp_path / "rejected",
            expected_commit_sha=commit_sha,
            commit_metadata={"sha": commit_sha, "commit": {"tree": {"sha": "b" * 40}}},
        )
    assert not (tmp_path / "rejected").exists()


def test_combined_pinned_extraction_rejects_wrong_resolved_commit_before_writing(tmp_path):
    archive = make_archive([("repo/file.txt", "file", "content")])
    with pytest.raises(SourceArchiveError, match="commit_sha_mismatch"):
        extract_and_verify_pinned_github_source_archive(
            archive,
            tmp_path / "rejected",
            expected_commit_sha="a" * 40,
            commit_metadata={"sha": "c" * 40, "commit": {"tree": {"sha": "b" * 40}}},
        )
    assert not (tmp_path / "rejected").exists()


def test_git_tree_sha_matches_git_for_mixed_names_modes_and_nested_directories(tmp_path):
    """Use Git itself as an oracle for tree ordering and mode serialization."""
    import shutil
    import subprocess

    git = shutil.which("git")
    if git is None:
        pytest.skip("git executable is unavailable")

    source = tmp_path / "source"
    source.mkdir()
    (source / "a").mkdir()
    (source / "a" / "child.txt").write_text("nested\n", encoding="utf-8")
    (source / "a.c").write_text("file sorts before directory a/\n", encoding="utf-8")
    (source / "café.txt").write_text("unicode filename\n", encoding="utf-8")
    executable = source / "run.sh"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)

    expected = compute_git_tree_sha(source)

    oracle = tmp_path / "git-oracle"
    oracle.mkdir()
    for child in source.iterdir():
        target = oracle / child.name
        if child.is_dir():
            shutil.copytree(child, target)
        else:
            shutil.copy2(child, target)

    subprocess.run([git, "-C", str(oracle), "init", "--quiet"], check=True)
    subprocess.run(
        [git, "-C", str(oracle), "config", "core.filemode", "true"],
        check=True,
    )
    subprocess.run([git, "-C", str(oracle), "add", "--all"], check=True)
    actual = subprocess.run(
        [git, "-C", str(oracle), "write-tree"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    assert expected == actual


def test_rejects_gzip_expansion_before_tar_header_parsing(tmp_path):
    compressed_bomb = gzip.compress(b"Z" * 100_000)
    destination = tmp_path / "source"
    with pytest.raises(SourceArchiveError, match="tar_uncompressed_size_out_of_bounds"):
        extract_github_source_archive(
            compressed_bomb,
            destination,
            limits=SourceArchiveLimits(
                max_archive_bytes=1024,
                max_uncompressed_bytes=1024,
                max_tar_uncompressed_bytes=4096,
            ),
        )
    assert not destination.exists()


def test_rejects_excessive_tar_member_metadata_during_iteration(tmp_path):
    archive = make_archive([
        ("root/", "dir", b""),
        ("root/a", "file", "a"),
        ("root/b", "file", "b"),
        ("root/c", "file", "c"),
    ])
    with pytest.raises(SourceArchiveError, match="member_count_out_of_bounds"):
        extract_github_source_archive(
            archive,
            tmp_path / "source",
            limits=SourceArchiveLimits(max_files=1),
        )
    assert not (tmp_path / "source").exists()
