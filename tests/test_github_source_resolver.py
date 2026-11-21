import io
import json
import tarfile

import pytest

from shared.source_archive import SourceArchiveLimits, compute_git_tree_sha
from shared.research_case import ResearchCase
from shared.target_execution_admission import AdmittedTarget, AdapterProfile
from shared.github_source_resolver import (
    GitHubSourceAcquisitionError,
    _validate_github_transport_url,
    acquire_allowlisted_pinned_github_source,
)


def _archive_with_file(name="repo/file.txt", payload=b"pinned"):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        info = tarfile.TarInfo("repo/")
        info.type = tarfile.DIRTYPE
        archive.addfile(info)
        info = tarfile.TarInfo(name)
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    return output.getvalue()


def _admitted_target(commit="a" * 40, repository="owner/repo"):
    case = ResearchCase(
        case_id="resolver-case",
        target_repository=repository,
        target_commit=commit,
        scope_url="https://example.com/scope",
        scope_digest="b" * 64,
        scope_reviewed_on="2026-11-14",
        hypothesis="Pinned source must match the registered commit.",
        attacker_capability="Repository content may be hostile.",
        expected_invariant="Only allowlisted pinned source is acquired.",
        falsification_criteria="Any mismatch is rejected.",
        execution_mode="local",
        status="ready",
    )
    return AdmittedTarget(
        task_id="task-1",
        case_id=case.case_id,
        round_id="round-1",
        round_spec_id=None,
        adapter_profile=AdapterProfile.SLITHER_STATIC,
        research_case=case,
        round_spec=None,
    )


class _FakeResponse:
    def __init__(self, body):
        self.body = body
        self.offset = 0
        self.headers = {"Content-Length": str(len(body))}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def geturl(self):
        return "https://api.github.com/final"

    def read(self, size=-1):
        if size < 0:
            size = len(self.body)
        chunk = self.body[self.offset:self.offset + size]
        self.offset += len(chunk)
        return chunk


def test_resolver_fetches_metadata_then_archive_for_exact_registered_pin(tmp_path, monkeypatch):
    from shared import github_source_resolver as resolver

    archive = _archive_with_file()
    extracted_root = tmp_path / "tree"
    extracted_root.mkdir()
    (extracted_root / "file.txt").write_bytes(b"pinned")
    tree_sha = compute_git_tree_sha(extracted_root)
    metadata = {
        "sha": "a" * 40,
        "commit": {"tree": {"sha": tree_sha}},
    }
    calls = []
    responses = iter([
        _FakeResponse(json.dumps(metadata).encode()),
        _FakeResponse(archive),
    ])

    def fake_open(url, timeout):
        calls.append((url, timeout))
        response = next(responses)
        response.geturl = lambda: url
        return response

    monkeypatch.setattr(resolver, "_open_response", fake_open)
    result = acquire_allowlisted_pinned_github_source(
        _admitted_target(),
        frozenset({"owner/repo"}),
        tmp_path / "acquired",
    )

    assert result.repository == "owner/repo"
    assert result.commit.commit_sha == "a" * 40
    assert result.commit.tree_sha == tree_sha
    assert (result.extracted.root / "file.txt").read_bytes() == b"pinned"
    assert calls == [
        ("https://api.github.com/repos/owner/repo/commits/" + "a" * 40, 15),
        ("https://api.github.com/repos/owner/repo/tarball/" + "a" * 40, 15),
    ]


def test_resolver_denies_repository_before_network_or_filesystem_changes(tmp_path, monkeypatch):
    from shared import github_source_resolver as resolver

    def unexpected(*_args, **_kwargs):
        pytest.fail("network must not be touched for a non-allowlisted target")

    monkeypatch.setattr(resolver, "_open_response", unexpected)
    destination = tmp_path / "source"
    with pytest.raises(GitHubSourceAcquisitionError, match="not_allowlisted"):
        acquire_allowlisted_pinned_github_source(
            _admitted_target(),
            frozenset({"other/repo"}),
            destination,
        )
    assert not destination.exists()


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
def test_resolver_rejects_malformed_archive_limits_before_network(
    tmp_path, monkeypatch, limits
):
    from shared import github_source_resolver as resolver

    def unexpected(*_args, **_kwargs):
        pytest.fail("network must not be touched for malformed resource budgets")

    monkeypatch.setattr(resolver, "_open_response", unexpected)
    with pytest.raises(
        GitHubSourceAcquisitionError, match="source_archive_limits_invalid"
    ):
        acquire_allowlisted_pinned_github_source(
            _admitted_target(),
            frozenset({"owner/repo"}),
            tmp_path / "source",
            limits=limits,
        )
    assert not (tmp_path / "source").exists()


def test_resolver_rejects_duplicate_commit_metadata_keys_before_archive_fetch(
    tmp_path, monkeypatch
):
    from shared import github_source_resolver as resolver

    calls = []

    def fake_open(url, timeout):
        calls.append(url)
        return _FakeResponse(
            b'{"sha":"' + b"a" * 40 + b'","sha":"' + b"b" * 40
            + b'","commit":{"tree":{"sha":"' + b"c" * 40 + b'"}}}'
        )

    monkeypatch.setattr(resolver, "_open_response", fake_open)
    with pytest.raises(
        GitHubSourceAcquisitionError, match="github_commit_metadata_duplicate_key"
    ):
        acquire_allowlisted_pinned_github_source(
            _admitted_target(),
            frozenset({"owner/repo"}),
            tmp_path / "source",
        )
    assert len(calls) == 1
    assert not (tmp_path / "source").exists()


def test_resolver_rejects_wrong_commit_metadata_before_archive_fetch(tmp_path, monkeypatch):
    from shared import github_source_resolver as resolver

    calls = []

    def fake_open(url, timeout):
        calls.append(url)
        return _FakeResponse(json.dumps({
            "sha": "c" * 40,
            "commit": {"tree": {"sha": "b" * 40}},
        }).encode())

    monkeypatch.setattr(resolver, "_open_response", fake_open)
    with pytest.raises(GitHubSourceAcquisitionError, match="commit_sha_mismatch"):
        acquire_allowlisted_pinned_github_source(
            _admitted_target(),
            frozenset({"owner/repo"}),
            tmp_path / "source",
        )
    assert len(calls) == 1
    assert not (tmp_path / "source").exists()


@pytest.mark.parametrize(
    "url",
    [
        "http://api.github.com/repos/owner/repo",
        "https://api.github.com.evil.example/repos/owner/repo",
        "https://user@api.github.com/repos/owner/repo",
        "https://api.github.com:443/repos/owner/repo",
        "https://evil.example/archive",
    ],
)
def test_redirect_policy_rejects_non_github_or_ambiguous_urls(url):
    with pytest.raises(GitHubSourceAcquisitionError):
        _validate_github_transport_url(url)


def test_redirect_policy_accepts_only_https_github_hosts():
    assert _validate_github_transport_url(
        "https://api.github.com/repos/owner/repo"
    ).startswith("https://")
    assert _validate_github_transport_url(
        "https://codeload.github.com/owner/repo/tar.gz/" + "a" * 40
    ).startswith("https://")


def test_resolver_enforces_streamed_archive_size_even_without_content_length(tmp_path, monkeypatch):
    from shared import github_source_resolver as resolver
    from shared.source_archive import SourceArchiveLimits

    archive = _archive_with_file()
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "file.txt").write_bytes(b"pinned")
    metadata = {
        "sha": "a" * 40,
        "commit": {"tree": {"sha": compute_git_tree_sha(tree)}},
    }

    class NoLengthResponse(_FakeResponse):
        def __init__(self, body):
            super().__init__(body)
            self.headers = {}

    responses = iter([
        _FakeResponse(json.dumps(metadata).encode()),
        NoLengthResponse(archive),
    ])

    def fake_open(url, timeout):
        return next(responses)

    monkeypatch.setattr(resolver, "_open_response", fake_open)
    with pytest.raises(GitHubSourceAcquisitionError, match="archive_too_large"):
        acquire_allowlisted_pinned_github_source(
            _admitted_target(),
            frozenset({"owner/repo"}),
            tmp_path / "source",
            limits=SourceArchiveLimits(max_archive_bytes=10),
        )
    assert not (tmp_path / "source").exists()
