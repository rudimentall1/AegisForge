"""Evidence-manifest integrity helpers for bounded EVM source review.

Hashes establish byte identity only. They do not establish source authenticity,
independent provenance, exploitability, runtime reproduction, or wallet exposure.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any


_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class EvidenceManifestError(ValueError):
    """Raised when an evidence record is incomplete or malformed."""


def sha256_text(text: str) -> str:
    """Return SHA-256 over the exact UTF-8 bytes of text; no normalization."""
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_evidence_record(
    *,
    repository: str,
    commit_sha: str,
    path: str,
    start_line: int,
    end_line: int,
    blob_sha: str,
    excerpt: str,
) -> dict[str, Any]:
    """Build a deterministic record for an exact source excerpt."""
    record = {
        "repository": repository,
        "commit_sha": commit_sha,
        "path": path,
        "start_line": start_line,
        "end_line": end_line,
        "git_blob_sha": blob_sha,
        "excerpt_sha256": sha256_text(excerpt),
        "excerpt": excerpt,
        "limitations": [
            "Hashes establish byte identity, not source authenticity.",
            "Pinned source text does not establish independent provenance.",
            "This record alone does not establish exploitability, runtime reproduction, or individual wallet exposure.",
        ],
    }
    validate_evidence_record(record)
    return record


def validate_evidence_record(record: dict[str, Any]) -> None:
    """Reject malformed provenance fields and internally inconsistent excerpt hashes."""
    if not isinstance(record, dict):
        raise EvidenceManifestError("record_must_be_object")

    repository = record.get("repository")
    if not isinstance(repository, str) or not _REPOSITORY_RE.fullmatch(repository):
        raise EvidenceManifestError("repository_must_be_owner_repo")

    commit_sha = record.get("commit_sha")
    if not isinstance(commit_sha, str) or not _SHA1_RE.fullmatch(commit_sha):
        raise EvidenceManifestError("commit_sha_must_be_40_lowercase_hex")

    path = record.get("path")
    if not isinstance(path, str) or not path.strip() or path.startswith("/") or ".." in path.split("/"):
        raise EvidenceManifestError("path_must_be_relative_repository_path")

    start_line = record.get("start_line")
    end_line = record.get("end_line")
    if type(start_line) is not int or type(end_line) is not int or start_line < 1 or end_line < start_line:
        raise EvidenceManifestError("line_range_invalid")

    blob_sha = record.get("git_blob_sha")
    if not isinstance(blob_sha, str) or not _SHA1_RE.fullmatch(blob_sha):
        raise EvidenceManifestError("git_blob_sha_must_be_40_lowercase_hex")

    excerpt = record.get("excerpt")
    if not isinstance(excerpt, str) or not excerpt:
        raise EvidenceManifestError("excerpt_required")

    digest = record.get("excerpt_sha256")
    if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        raise EvidenceManifestError("excerpt_sha256_must_be_64_lowercase_hex")
    if sha256_text(excerpt) != digest:
        raise EvidenceManifestError("excerpt_sha256_mismatch")

    limitations = record.get("limitations")
    if not isinstance(limitations, list) or not all(isinstance(item, str) and item.strip() for item in limitations):
        raise EvidenceManifestError("limitations_must_be_nonempty_string_list")
    joined = " ".join(limitations).lower()
    if "source authenticity" not in joined or "independent provenance" not in joined:
        raise EvidenceManifestError("limitations_must_separate_hash_integrity_from_provenance")
