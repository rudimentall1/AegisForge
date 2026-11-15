"""Fetch and verify a GitHub source archive for an immutable commit.

Network acquisition is deliberately separate from extraction and execution.
This module never executes repository content and never forwards credentials.
"""
from __future__ import annotations

import json
import math
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from shared.source_archive import (
    ExtractedSource,
    PinnedCommit,
    SourceArchiveError,
    SourceArchiveLimits,
    extract_and_verify_pinned_github_source_archive,
    validate_pinned_commit_metadata,
)


class GitHubSourceFetchError(RuntimeError):
    """Pinned source acquisition failed closed."""


@dataclass(frozen=True, slots=True)
class GitHubSourceFetchLimits:
    max_metadata_bytes: int = 1024 * 1024
    timeout_seconds: float = 20.0


class _AllowlistedHTTPSRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: set[str]) -> None:
        super().__init__()
        self._allowed_hosts = frozenset(allowed_hosts)

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in self._allowed_hosts
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in (None, 443)
        ):
            raise GitHubSourceFetchError("github_redirect_rejected")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _read_bounded(response: Any, maximum: int, error_code: str) -> bytes:
    if maximum <= 0:
        raise GitHubSourceFetchError("response_limit_invalid")
    raw_length = response.headers.get("Content-Length")
    if raw_length is not None:
        try:
            declared_length = int(raw_length)
        except (TypeError, ValueError) as exc:
            raise GitHubSourceFetchError("response_content_length_invalid") from exc
        if declared_length < 0 or declared_length > maximum:
            raise GitHubSourceFetchError(error_code)
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(min(1024 * 1024, maximum + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > maximum:
            raise GitHubSourceFetchError(error_code)
        chunks.append(chunk)
    return b"".join(chunks)


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GitHubSourceFetchError("commit_metadata_duplicate_key")
        result[key] = value
    return result


def _validate_repo_component(value: str) -> str:
    if (
        not isinstance(value, str)
        or value in {"", ".", ".."}
        or re.fullmatch(r"[A-Za-z0-9_.-]+", value) is None
    ):
        raise GitHubSourceFetchError("github_repository_identifier_invalid")
    return value


def fetch_and_extract_pinned_github_source(
    owner: str,
    repository: str,
    expected_commit_sha: str,
    destination: str,
    *,
    archive_limits: SourceArchiveLimits = SourceArchiveLimits(),
    fetch_limits: GitHubSourceFetchLimits = GitHubSourceFetchLimits(),
) -> tuple[ExtractedSource, PinnedCommit]:
    """Fetch GitHub commit metadata and its exact-SHA tarball, then verify its tree.

    The API response is resolved before archive acquisition. Redirects are
    restricted to GitHub API and codeload hosts, response bodies are bounded,
    and no Authorization header or ambient credential is used.
    """
    owner = _validate_repo_component(owner)
    repository = _validate_repo_component(repository)
    if (
        not isinstance(expected_commit_sha, str)
        or re.fullmatch(r"[0-9a-fA-F]{40}", expected_commit_sha) is None
    ):
        raise GitHubSourceFetchError("full_commit_sha_required")
    if (
        isinstance(fetch_limits.timeout_seconds, bool)
        or not isinstance(fetch_limits.timeout_seconds, (int, float))
        or not math.isfinite(fetch_limits.timeout_seconds)
        or fetch_limits.timeout_seconds <= 0
        or isinstance(fetch_limits.max_metadata_bytes, bool)
        or not isinstance(fetch_limits.max_metadata_bytes, int)
        or fetch_limits.max_metadata_bytes <= 0
        or isinstance(archive_limits.max_archive_bytes, bool)
        or not isinstance(archive_limits.max_archive_bytes, int)
        or archive_limits.max_archive_bytes <= 0
    ):
        raise GitHubSourceFetchError("fetch_limits_invalid")

    commit_sha = expected_commit_sha.lower()
    encoded_owner = urllib.parse.quote(owner, safe="")
    encoded_repository = urllib.parse.quote(repository, safe="")
    metadata_url = (
        f"https://api.github.com/repos/{encoded_owner}/{encoded_repository}"
        f"/commits/{commit_sha}"
    )
    archive_url = (
        f"https://api.github.com/repos/{encoded_owner}/{encoded_repository}"
        f"/tarball/{commit_sha}"
    )

    metadata_opener = urllib.request.build_opener(
        _AllowlistedHTTPSRedirectHandler({"api.github.com"})
    )
    archive_opener = urllib.request.build_opener(
        _AllowlistedHTTPSRedirectHandler({"api.github.com", "codeload.github.com"})
    )

    def request_bytes(opener, url: str, maximum: int, error_code: str) -> bytes:
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "AegisForge-pinned-source-fetch/1",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            method="GET",
        )
        try:
            with opener.open(request, timeout=fetch_limits.timeout_seconds) as response:
                if response.getcode() != 200:
                    raise GitHubSourceFetchError("github_http_status_rejected")
                return _read_bounded(response, maximum, error_code)
        except GitHubSourceFetchError:
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise GitHubSourceFetchError("github_request_failed") from exc

    metadata_bytes = request_bytes(
        metadata_opener,
        metadata_url,
        fetch_limits.max_metadata_bytes,
        "commit_metadata_size_out_of_bounds",
    )
    try:
        metadata = json.loads(
            metadata_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except GitHubSourceFetchError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GitHubSourceFetchError("commit_metadata_invalid") from exc

    try:
        validate_pinned_commit_metadata(commit_sha, metadata)
    except SourceArchiveError as exc:
        raise GitHubSourceFetchError(str(exc)) from exc

    archive_bytes = request_bytes(
        archive_opener,
        archive_url,
        archive_limits.max_archive_bytes,
        "source_archive_size_out_of_bounds",
    )
    try:
        return extract_and_verify_pinned_github_source_archive(
            archive_bytes,
            destination,
            expected_commit_sha=commit_sha,
            commit_metadata=metadata,
            limits=archive_limits,
        )
    except SourceArchiveError as exc:
        raise GitHubSourceFetchError(str(exc)) from exc
