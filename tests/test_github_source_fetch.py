import gzip
import io
import json
import tarfile
from pathlib import Path

import pytest

from shared import github_source_fetch as fetch
from shared.source_archive import compute_git_tree_sha


class FakeResponse:
    def __init__(self, payload: bytes):
        self._stream = io.BytesIO(payload)
        self.headers = {"Content-Length": str(len(payload))}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def getcode(self):
        return 200

    def read(self, size=-1):
        return self._stream.read(size)


class FakeOpener:
    def __init__(self, payload: bytes):
        self.payload = payload
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return FakeResponse(self.payload)


def make_archive():
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        data = b"pinned source\n"
        info = tarfile.TarInfo("repo-pinned/file.txt")
        info.size = len(data)
        info.mode = 0o644
        archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def test_fetches_exact_commit_and_verifies_archive_tree(tmp_path, monkeypatch):
    archive = make_archive()
    expected_root = tmp_path / "expected"
    expected_root.mkdir()
    (expected_root / "file.txt").write_bytes(b"pinned source\n")
    tree_sha = compute_git_tree_sha(expected_root)
    commit_sha = "a" * 40
    metadata = json.dumps({
        "sha": commit_sha,
        "commit": {"tree": {"sha": tree_sha}},
    }).encode()
    payloads = iter([metadata, archive])
    created = []

    def build_opener(*_args):
        opener = FakeOpener(next(payloads))
        created.append(opener)
        return opener

    monkeypatch.setattr(fetch.urllib.request, "build_opener", build_opener)

    extracted, pinned = fetch.fetch_and_extract_pinned_github_source(
        "owner", "repo", commit_sha, str(tmp_path / "output")
    )

    assert pinned.commit_sha == commit_sha
    assert pinned.tree_sha == tree_sha
    assert (extracted.root / "file.txt").read_bytes() == b"pinned source\n"


def test_rejects_wrong_resolved_commit_before_archive_request(tmp_path, monkeypatch):
    metadata = json.dumps({
        "sha": "b" * 40,
        "commit": {"tree": {"sha": "c" * 40}},
    }).encode()
    payloads = iter([metadata, b"unused"])
    created = []

    def build_opener(*_args):
        opener = FakeOpener(next(payloads))
        created.append(opener)
        return opener

    monkeypatch.setattr(fetch.urllib.request, "build_opener", build_opener)

    with pytest.raises(fetch.GitHubSourceFetchError, match="resolved_commit_sha_mismatch"):
        fetch.fetch_and_extract_pinned_github_source(
            "owner", "repo", "a" * 40, str(tmp_path / "output")
        )

    assert len(created) == 2
    assert created[1].requests == []
    assert not (tmp_path / "output").exists()


def test_rejects_duplicate_metadata_keys(tmp_path, monkeypatch):
    metadata = (
        b'{"sha":"' + b"a" * 40 +
        b'","sha":"' + b"a" * 40 +
        b'","commit":{"tree":{"sha":"' + b"b" * 40 + b'"}}}'
    )
    created = []

    def build_opener(*_args):
        opener = FakeOpener(metadata)
        created.append(opener)
        return opener

    monkeypatch.setattr(fetch.urllib.request, "build_opener", build_opener)

    with pytest.raises(fetch.GitHubSourceFetchError, match="duplicate_key"):
        fetch.fetch_and_extract_pinned_github_source(
            "owner", "repo", "a" * 40, str(tmp_path / "output")
        )


def test_rejects_redirect_outside_github_allowlist():
    handler = fetch._AllowlistedHTTPSRedirectHandler({"api.github.com"})
    with pytest.raises(fetch.GitHubSourceFetchError, match="redirect_rejected"):
        handler.redirect_request(
            None, None, 302, "Found", {}, "https://attacker.example/archive"
        )


def test_rejects_oversized_response_body():
    response = FakeResponse(b"x" * 20)
    with pytest.raises(fetch.GitHubSourceFetchError, match="size_out_of_bounds"):
        fetch._read_bounded(response, 10, "response_size_out_of_bounds")
