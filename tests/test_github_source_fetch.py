import io
import json
import tarfile

import pytest

from shared import github_source_fetch as fetch
from shared.source_archive import SourceArchiveLimits, compute_git_tree_sha


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
    metadata_request = created[0].requests[0][0]
    archive_request = created[1].requests[0][0]
    assert metadata_request.full_url.endswith(f"/commits/{commit_sha}")
    assert archive_request.full_url.endswith(f"/tarball/{commit_sha}")
    assert all(
        key.lower() != "authorization"
        for request, _timeout in (created[0].requests + created[1].requests)
        for key, _value in request.header_items()
    )



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



def test_rejects_non_finite_or_boolean_fetch_limits_before_network(tmp_path, monkeypatch):
    def fail_if_network_is_constructed(*_args, **_kwargs):
        raise AssertionError("network opener must not be constructed")

    monkeypatch.setattr(
        fetch.urllib.request, "build_opener", fail_if_network_is_constructed
    )
    invalid_limits = [
        fetch.GitHubSourceFetchLimits(timeout_seconds=float("nan")),
        fetch.GitHubSourceFetchLimits(timeout_seconds=float("inf")),
        fetch.GitHubSourceFetchLimits(timeout_seconds=True),
        fetch.GitHubSourceFetchLimits(max_metadata_bytes=True),
    ]
    for limits in invalid_limits:
        with pytest.raises(fetch.GitHubSourceFetchError, match="fetch_limits_invalid"):
            fetch.fetch_and_extract_pinned_github_source(
                "owner", "repo", "a" * 40, str(tmp_path / "output"),
                fetch_limits=limits,
            )


@pytest.mark.parametrize(
    "limits",
    [
        SourceArchiveLimits(max_archive_bytes=True),
        SourceArchiveLimits(max_uncompressed_bytes=float("nan")),
        SourceArchiveLimits(max_tar_uncompressed_bytes=float("inf")),
        SourceArchiveLimits(max_files=1.5),
        SourceArchiveLimits(max_files=False),
    ],
)
def test_rejects_malformed_archive_limits_before_network(
    tmp_path, monkeypatch, limits
):
    def fail_if_network_is_constructed(*_args, **_kwargs):
        raise AssertionError("network opener must not be constructed")

    monkeypatch.setattr(
        fetch.urllib.request, "build_opener", fail_if_network_is_constructed
    )
    with pytest.raises(fetch.GitHubSourceFetchError, match="fetch_limits_invalid"):
        fetch.fetch_and_extract_pinned_github_source(
            "owner", "repo", "a" * 40, str(tmp_path / "output"),
            archive_limits=limits,
        )


def test_rejects_invalid_archive_limit_before_network(tmp_path, monkeypatch):
    def fail_if_network_is_constructed(*_args, **_kwargs):
        raise AssertionError("network opener must not be constructed")

    monkeypatch.setattr(
        fetch.urllib.request, "build_opener", fail_if_network_is_constructed
    )
    from shared.source_archive import SourceArchiveLimits

    with pytest.raises(fetch.GitHubSourceFetchError, match="fetch_limits_invalid"):
        fetch.fetch_and_extract_pinned_github_source(
            "owner", "repo", "a" * 40, str(tmp_path / "output"),
            archive_limits=SourceArchiveLimits(max_archive_bytes=0),
        )


def test_rejects_redirect_with_nonstandard_port_or_userinfo():
    handler = fetch._AllowlistedHTTPSRedirectHandler({"api.github.com"})
    for target in (
        "https://api.github.com:8443/archive",
        "https://user@api.github.com/archive",
        "http://api.github.com/archive",
    ):
        with pytest.raises(fetch.GitHubSourceFetchError, match="redirect_rejected"):
            handler.redirect_request(None, None, 302, "Found", {}, target)


def test_rejects_oversized_declared_content_length():
    response = FakeResponse(b"x")
    response.headers["Content-Length"] = "999"
    with pytest.raises(fetch.GitHubSourceFetchError, match="size_out_of_bounds"):
        fetch._read_bounded(response, 10, "response_size_out_of_bounds")
