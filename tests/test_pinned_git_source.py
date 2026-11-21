import hashlib
import subprocess

import pytest

from shared.pinned_git_source import PinnedSourceError, load_pinned_solidity_sources


def make_repository(tmp_path):
    root = tmp_path / "target"
    root.mkdir()
    subprocess.run(["git", "init", str(root)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
    source = root / "src" / "Vault.sol"
    source.parent.mkdir()
    source.write_text("pragma solidity 0.8.24; contract Vault {}\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "src/Vault.sol"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-m", "fixture"], check=True, capture_output=True)
    commit = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    subprocess.run(
        ["git", "-C", str(root), "remote", "add", "origin", "https://github.com/acme/vault.git"],
        check=True,
    )
    return root, commit


def test_loads_solidity_from_exact_pinned_commit_not_worktree(tmp_path):
    root, commit = make_repository(tmp_path)
    (root / "src" / "Vault.sol").write_text("contract Tampered {}\n", encoding="utf-8")

    result = load_pinned_solidity_sources(
        root, repository="acme/vault", commit_sha=commit, source_paths=["src/Vault.sol"]
    )

    expected = "pragma solidity 0.8.24; contract Vault {}\n"
    assert result["sources"] == {"src/Vault.sol": expected}
    assert result["source_sha256"] == {
        "src/Vault.sol": hashlib.sha256(expected.encode()).hexdigest()
    }
    assert result["target_commit"] == commit


def test_rejects_checkout_at_different_head(tmp_path):
    root, commit = make_repository(tmp_path)
    with pytest.raises(PinnedSourceError, match="target_git_revision_mismatch"):
        load_pinned_solidity_sources(
            root, repository="acme/vault", commit_sha="0" * 40, source_paths=["src/Vault.sol"]
        )


def test_rejects_origin_repository_mismatch(tmp_path):
    root, commit = make_repository(tmp_path)
    subprocess.run(
        ["git", "-C", str(root), "remote", "set-url", "origin", "https://github.com/attacker/vault.git"],
        check=True,
    )
    with pytest.raises(PinnedSourceError, match="target_git_origin_mismatch"):
        load_pinned_solidity_sources(
            root, repository="acme/vault", commit_sha=commit, source_paths=["src/Vault.sol"]
        )


@pytest.mark.parametrize("path", ["../Vault.sol", "/etc/passwd", "src\\Vault.sol", "foundry.toml"])
def test_rejects_unsafe_or_non_solidity_paths(tmp_path, path):
    root, commit = make_repository(tmp_path)
    with pytest.raises(PinnedSourceError):
        load_pinned_solidity_sources(
            root, repository="acme/vault", commit_sha=commit, source_paths=[path]
        )


def test_rejects_missing_source_and_empty_path_list(tmp_path):
    root, commit = make_repository(tmp_path)
    with pytest.raises(PinnedSourceError, match="target_source_file_missing"):
        load_pinned_solidity_sources(
            root, repository="acme/vault", commit_sha=commit, source_paths=["src/Missing.sol"]
        )
    with pytest.raises(PinnedSourceError, match="source_paths_required"):
        load_pinned_solidity_sources(
            root, repository="acme/vault", commit_sha=commit, source_paths=[]
        )


def test_rejects_oversized_blob_before_loading_source(tmp_path):
    root, commit = make_repository(tmp_path)
    with pytest.raises(PinnedSourceError, match="source_bytes_exceeded"):
        load_pinned_solidity_sources(
            root, repository="acme/vault", commit_sha=commit,
            source_paths=["src/Vault.sol"], max_bytes=8,
        )


def test_rejects_symlink_checkout_root(tmp_path):
    root, commit = make_repository(tmp_path)
    alias = tmp_path / "checkout-link"
    alias.symlink_to(root, target_is_directory=True)
    with pytest.raises(PinnedSourceError, match="target_git_checkout_required"):
        load_pinned_solidity_sources(
            alias, repository="acme/vault", commit_sha=commit,
            source_paths=["src/Vault.sol"],
        )
