"""Bounded, non-executing acquisition of allowlisted pinned GitHub source.

Network access is deliberately limited to GitHub's commit API and codeload
archive host. This module never executes target content or installs dependencies.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from shared.repository_policy import (
    RepositoryPolicyError,
    authorize_admitted_target_source,
)
from shared.source_archive import (
    ExtractedSource,
    PinnedCommit,
    SourceArchiveError,
    SourceArchiveLimits,
    extract_and_verify_pinned_github_source_archive,
    validate_source_archive_limits,
)
from shared.target_execution_admission import AdmittedTarget


_ALLOWED_REDIRECT_HOSTS = frozenset({"api.github.com", "codeload.github.com"})
_MAX_REDIRECTS = 3
_MAX_METADATA_BYTES = 1024 * 1024
_DEFAULT_TIMEOUT_SECONDS = 15


class GitHubSourceAcquisitionError(ValueError):
    """Pinned source acquisition failed closed."""


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GitHubSourceAcquisitionError("github_commit_metadata_duplicate_key")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class AcquiredPinnedSource:
    repository: str
    commit: PinnedCommit
    extracted: ExtractedSource


def _validate_github_transport_url(url: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise GitHubSourceAcquisitionError("github_redirect_url_invalid") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname not in _ALLOWED_REDIRECT_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.fragment
    ):
        raise GitHubSourceAcquisitionError("github_redirect_destination_rejected")
    return url


class _PinnedGitHubRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Permit only bounded HTTPS redirects between fixed GitHub hosts."""

    def __init__(self) -> None:
        super().__init__()
        self._redirect_count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self._redirect_count += 1
        if self._redirect_count > _MAX_REDIRECTS:
            raise GitHubSourceAcquisitionError("github_redirect_limit_exceeded")
        _validate_github_transport_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open_response(url: str, timeout: int):
    _validate_github_transport_url(url)
    opener = urllib.request.build_opener(_PinnedGitHubRedirectHandler())
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "AegisForge-Pinned-Source/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="GET",
    )
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        # Do not expose response bodies, URLs with query data, or credentials.
        raise GitHubSourceAcquisitionError(
            f"github_http_status_{exc.code}"
        ) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise GitHubSourceAcquisitionError("github_transport_failed") from exc
    final_url = response.geturl()
    _validate_github_transport_url(final_url)
    return response


def _read_bounded_response(response, maximum: int, error_code: str) -> bytes:
    if maximum <= 0:
        raise GitHubSourceAcquisitionError("source_response_limit_invalid")
    raw_length = response.headers.get("Content-Length")
    if raw_length is not None:
        try:
            declared_length = int(raw_length)
        except (TypeError, ValueError) as exc:
            raise GitHubSourceAcquisitionError("github_content_length_invalid") from exc
        if declared_length < 0 or declared_length > maximum:
            raise GitHubSourceAcquisitionError(error_code)
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(min(1024 * 1024, maximum + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > maximum:
            raise GitHubSourceAcquisitionError(error_code)
        chunks.append(chunk)
    return b"".join(chunks)


def acquire_allowlisted_pinned_github_source(
    admitted_target: AdmittedTarget,
    allowed_repositories: frozenset[str],
    destination: str | Path,
    *,
    limits: SourceArchiveLimits = SourceArchiveLimits(),
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
) -> AcquiredPinnedSource:
    """Fetch and verify only the repository+commit bound to admitted case state.

    The allowlist is server-owned configuration. No URL, owner, repository,
    commit, redirect target, or archive path is accepted from the caller.
    """
    if not isinstance(admitted_target, AdmittedTarget):
        raise GitHubSourceAcquisitionError("admitted_target_required")
    try:
        validate_source_archive_limits(limits)
    except SourceArchiveError as exc:
        raise GitHubSourceAcquisitionError("source_archive_limits_invalid") from exc
    if (
        not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or timeout_seconds <= 0
        or timeout_seconds > 60
    ):
        raise GitHubSourceAcquisitionError("source_timeout_out_of_bounds")
    try:
        admitted, repository = authorize_admitted_target_source(
            admitted_target,
            allowed_repositories,
        )
    except RepositoryPolicyError as exc:
        raise GitHubSourceAcquisitionError(str(exc)) from exc

    commit_sha = admitted.research_case.target_commit
    if (
        not isinstance(commit_sha, str)
        or len(commit_sha) != 40
        or not re.fullmatch(r"[0-9a-fA-F]{40}", commit_sha)
    ):
        raise GitHubSourceAcquisitionError("full_pinned_commit_sha_required")

    target = Path(destination)
    if target.exists() or target.is_symlink():
        raise GitHubSourceAcquisitionError("source_destination_must_not_exist")

    owner = urllib.parse.quote(repository.owner, safe="")
    repo = urllib.parse.quote(repository.repository, safe="")
    pin = commit_sha.lower()
    api_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{pin}"
    archive_url = f"https://api.github.com/repos/{owner}/{repo}/tarball/{pin}"

    with _open_response(api_url, timeout_seconds) as response:
        metadata_bytes = _read_bounded_response(
            response, _MAX_METADATA_BYTES, "github_commit_metadata_too_large"
        )
    try:
        metadata = json.loads(
            metadata_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GitHubSourceAcquisitionError("github_commit_metadata_invalid") from exc

    # Validate the exact returned commit before making the archive request.
    from shared.source_archive import validate_pinned_commit_metadata
    try:
        pinned = validate_pinned_commit_metadata(pin, metadata)
    except SourceArchiveError as exc:
        raise GitHubSourceAcquisitionError(str(exc)) from exc

    with _open_response(archive_url, timeout_seconds) as response:
        archive_bytes = _read_bounded_response(
            response, limits.max_archive_bytes, "github_archive_too_large"
        )

    try:
        extracted, verified_pin = extract_and_verify_pinned_github_source_archive(
            archive_bytes,
            target,
            expected_commit_sha=pin,
            commit_metadata=metadata,
            limits=limits,
        )
    except SourceArchiveError as exc:
        raise GitHubSourceAcquisitionError(str(exc)) from exc

    if verified_pin != pinned:
        # Defensive consistency check; both values came from the same metadata.
        import shutil
        shutil.rmtree(target, ignore_errors=True)
        raise GitHubSourceAcquisitionError("pinned_commit_identity_changed")
    return AcquiredPinnedSource(
        repository=repository.full_name,
        commit=verified_pin,
        extracted=extracted,
    )
