"""Trusted repository authorization for pinned-target source acquisition.

The ResearchCase schema remains backward-compatible and may contain a GitHub
shorthand or HTTPS URL. This module is the stricter server-side boundary used
before any source-network access. An empty allowlist denies every repository.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from shared.research_case import ResearchCase\nfrom shared.target_execution_admission import AdmittedTarget


class RepositoryPolicyError(ValueError):
    """A target repository is not authorized for source acquisition."""


_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_ENV_ALLOWLIST = "AEGISFORGE_ALLOWED_TARGET_REPOSITORIES"


@dataclass(frozen=True, slots=True)
class AuthorizedRepository:
    """Canonical GitHub repository identity authorized by local policy."""

    owner: str
    repository: str

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.repository}"

    @property
    def clone_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repository}.git"


def _validate_segments(owner: str, repository: str) -> tuple[str, str]:
    for label, value in (("owner", owner), ("repository", repository)):
        if (
            not isinstance(value, str)
            or not value
            or value in {".", ".."}
            or not _SEGMENT_RE.fullmatch(value)
            or value.startswith(".")
            or value.endswith(".")
        ):
            raise RepositoryPolicyError(f"repository_{label}_invalid")
    return owner, repository


def parse_github_repository(value: str) -> AuthorizedRepository:
    """Parse only owner/repo or canonical https://github.com/owner/repo[.git]."""
    if not isinstance(value, str) or not value or value != value.strip():
        raise RepositoryPolicyError("repository_identifier_invalid")
    if any(ord(char) < 32 for char in value) or "\\" in value or "%" in value:
        raise RepositoryPolicyError("repository_identifier_ambiguous")

    if "://" not in value:
        if value.count("/") != 1:
            raise RepositoryPolicyError("repository_shorthand_invalid")
        owner, repository = value.split("/", 1)
        owner, repository = _validate_segments(owner, repository)
        return AuthorizedRepository(owner, repository)

    try:
        parsed = urlsplit(value)
        # Exact netloc rejects credentials, explicit ports, trailing dots,
        # alternate hosts, and host aliases before any request is made.
        if (
            parsed.scheme != "https"
            or parsed.netloc != "github.com"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.query
            or parsed.fragment
        ):
            raise RepositoryPolicyError("repository_url_not_canonical_github")
        path = parsed.path
        if not path.startswith("/") or path.endswith("/"):
            raise RepositoryPolicyError("repository_url_path_invalid")
        parts = path[1:].split("/")
        if len(parts) != 2:
            raise RepositoryPolicyError("repository_url_path_invalid")
        owner, repository = parts
        if repository.endswith(".git"):
            repository = repository[:-4]
        owner, repository = _validate_segments(owner, repository)
        return AuthorizedRepository(owner, repository)
    except ValueError as exc:
        if isinstance(exc, RepositoryPolicyError):
            raise
        raise RepositoryPolicyError("repository_url_invalid") from exc


def parse_repository_allowlist(values) -> frozenset[str]:
    """Normalize an explicit iterable of trusted owner/repo identifiers."""
    if values is None:
        return frozenset()
    normalized: set[str] = set()
    for value in values:
        parsed = parse_github_repository(value)
        normalized.add(parsed.full_name.casefold())
    return frozenset(normalized)


def load_repository_allowlist(environ=None) -> frozenset[str]:
    """Load a comma-separated server-owned allowlist; unset/empty means deny all."""
    source = os.environ if environ is None else environ
    raw = source.get(_ENV_ALLOWLIST, "")
    if not isinstance(raw, str):
        raise RepositoryPolicyError("repository_allowlist_configuration_invalid")
    entries = [item.strip() for item in raw.split(",") if item.strip()]
    return parse_repository_allowlist(entries)


def authorize_case_repository(
    case: ResearchCase,
    allowed_repositories: frozenset[str],
) -> AuthorizedRepository:
    """Authorize the immutable case target against an explicit server policy.

    The policy is an independent argument and must never be populated from a
    task, request body, agent output, case field, or evidence bundle.
    """
    if not isinstance(case, ResearchCase):
        raise RepositoryPolicyError("registered_research_case_required")
    if not isinstance(allowed_repositories, frozenset) or not allowed_repositories:
        raise RepositoryPolicyError("repository_allowlist_empty_or_untrusted")
    target = parse_github_repository(case.target_repository)
    if target.full_name.casefold() not in allowed_repositories:
        raise RepositoryPolicyError("repository_not_allowlisted")
    return target



def authorize_admitted_target_source(
    admitted_target: AdmittedTarget,
    allowed_repositories: frozenset[str],
) -> tuple[AdmittedTarget, AuthorizedRepository]:
    """Apply repository policy to an already admitted, registry-resolved target.

    Source-acquisition code must call this function before opening any network
    connection. It deliberately accepts no repository or URL from the caller.
    """
    if not isinstance(admitted_target, AdmittedTarget):
        raise RepositoryPolicyError("admitted_target_required")
    repository = authorize_case_repository(
        admitted_target.research_case,
        allowed_repositories,
    )
    return admitted_target, repository
