import subprocess

import pytest

from shared.git_source_pin_verifier import GitSourcePinError, verify_git_source_pin


REPOSITORY = "example/pinned-source"


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def committed_repo(tmp_path):
    repo = tmp_path / "source"
    repo.mkdir()
    git_init = subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    git(repo, "config", "user.name", "Test")
    git(repo, "config", "user.email", "test@example.invalid")
    source = repo / "src" / "sample.py"
    source.parent.mkdir()
    source.write_bytes(b"first line\nsecond line\n")
    git(repo, "add", "src/sample.py")
    git(repo, "commit", "-m", "add pinned source")
    commit = git(repo, "rev-parse", "HEAD")
    blob = git(repo, "rev-parse", f"{commit}:src/sample.py")
    return repo, commit, blob


def verify(repo, commit, blob, **overrides):
    args = {
        "expected_repository": REPOSITORY,
        "expected_commit_sha": commit,
        "expected_path": "src/sample.py",
        "expected_blob_sha": blob,
    }
    args.update(overrides)
    return verify_git_source_pin(repo, **args)


def test_verifies_exact_commit_path_and_blob(committed_repo):
    repo, commit, blob = committed_repo
    result = verify(repo, commit, blob)
    assert result["valid"] is True
    assert result["commit_sha"] == commit
    assert result["git_blob_sha"] == blob
    assert result["git_object_match"] is True
    assert result["provenance_verified"] is False


def test_rejects_blob_pin_mismatch(committed_repo):
    repo, commit, _ = committed_repo
    with pytest.raises(GitSourcePinError, match="git_blob_sha_mismatch"):
        verify(repo, commit, "0" * 40)


def test_rejects_invalid_commit_pin(committed_repo):
    repo, _, blob = committed_repo
    with pytest.raises(GitSourcePinError, match="expected_commit_sha_invalid"):
        verify(repo, "HEAD", blob)


@pytest.mark.parametrize(
    "path",
    [
        "../sample.py",
        "/etc/passwd",
        "src\\\\sample.py",
        "src//sample.py",
        "src/line\\nbreak.py",
        "src/tab\\tname.py",
        "src/delete\\x7fname.py",
        "src/null\\x00byte.py",
    ],
)
def test_rejects_unsafe_path(committed_repo, path):
    repo, commit, blob = committed_repo
    with pytest.raises(GitSourcePinError, match="expected_path_invalid"):
        verify(repo, commit, blob, expected_path=path)


def test_rejects_symlink_even_when_its_blob_hash_matches(committed_repo):
    repo, _, _ = committed_repo
    link = repo / "src" / "sample-link.py"
    link.symlink_to("sample.py")
    git(repo, "add", "src/sample-link.py")
    git(repo, "commit", "-m", "add source symlink")
    commit = git(repo, "rev-parse", "HEAD")
    blob = git(repo, "rev-parse", f"{commit}:src/sample-link.py")

    with pytest.raises(GitSourcePinError, match="git_path_not_regular_file"):
        verify(
            repo,
            commit,
            blob,
            expected_path="src/sample-link.py",
        )


def test_rejects_file_absent_from_pinned_commit(committed_repo):
    repo, commit, _ = committed_repo
    with pytest.raises(GitSourcePinError, match="git_object_unavailable"):
        verify(repo, commit, "0" * 40, expected_path="missing.py")

def test_rejects_missing_repository_label(committed_repo):
    repo, commit, blob = committed_repo
    with pytest.raises(GitSourcePinError, match="expected_repository_required"):
        verify(repo, commit, blob, expected_repository=" ")


def test_rejects_malformed_blob_pin(committed_repo):
    repo, commit, _ = committed_repo
    with pytest.raises(GitSourcePinError, match="expected_blob_sha_invalid"):
        verify(repo, commit, "not-a-sha")

def test_treats_glob_characters_as_literal_path(committed_repo):
    repo, commit, blob = committed_repo
    with pytest.raises(GitSourcePinError, match="git_object_unavailable"):
        verify(repo, commit, blob, expected_path="src/*.py")

    literal_file = repo / "src" / "*.py"
    literal_file.write_bytes(b"literal wildcard filename\\n")
    git(repo, "add", "--", "src/*.py")
    git(repo, "commit", "-m", "add literal wildcard filename")
    commit = git(repo, "rev-parse", "HEAD")
    blob = git(repo, "rev-parse", f"{commit}:src/*.py")

    result = verify(repo, commit, blob, expected_path="src/*.py")
    assert result["valid"] is True
    assert result["path"] == "src/*.py"


def test_ignores_inherited_git_dir_environment(committed_repo, tmp_path, monkeypatch):
    repo, commit, blob = committed_repo
    other_repo = tmp_path / "other"
    other_repo.mkdir()
    git_init = subprocess.run(["git", "init", str(other_repo)], check=True, capture_output=True)
    monkeypatch.setenv("GIT_DIR", str(other_repo / ".git"))

    result = verify(repo, commit, blob)
    assert result["valid"] is True
    assert result["commit_sha"] == commit

def test_ignores_git_replace_refs(committed_repo):
    repo, original_commit, original_blob = committed_repo
    source = repo / "src" / "sample.py"
    source.write_bytes(b"replacement commit content\\n")
    git(repo, "add", "src/sample.py")
    git(repo, "commit", "-m", "create replacement commit")
    replacement_commit = git(repo, "rev-parse", "HEAD")
    git(repo, "replace", original_commit, replacement_commit)

    result = verify(repo, original_commit, original_blob)
    assert result["valid"] is True
    assert result["commit_sha"] == original_commit
    assert result["git_blob_sha"] == original_blob

