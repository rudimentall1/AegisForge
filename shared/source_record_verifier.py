"""Offline verification of source-excerpt records against caller-supplied file bytes.

This module deliberately performs no network access. The caller is responsible for
obtaining the bytes and independently deciding whether the repository/revision
is an appropriate source. Matching hashes establish byte identity, not provenance.
"""
import hashlib
import re


class SourceRecordVerificationError(ValueError):
    """Raised when a source record does not match supplied source bytes."""


_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_SOURCE_RECORD_BYTES = 16 * 1024 * 1024


def _git_blob_sha1(content: bytes) -> str:
    if not isinstance(content, bytes):
        raise SourceRecordVerificationError("source_bytes_required")
    header = b"blob " + str(len(content)).encode("ascii") + b"\0"
    return hashlib.sha1(header + content).hexdigest()


def verify_source_record_against_bytes(
    record,
    source_bytes,
    *,
    expected_repository,
    expected_commit_sha,
    expected_path,
):
    """Check coordinates and hashes against exact bytes supplied by the caller.

    Lines are 1-based and inclusive. Excerpt bytes are the exact UTF-8 encoding
    of the selected source lines, preserving original newline characters.
    This verifies consistency only; it does not fetch or authenticate a revision.
    """
    if not isinstance(record, dict):
        raise SourceRecordVerificationError("source_record_must_be_object")
    if not isinstance(source_bytes, bytes):
        raise SourceRecordVerificationError("source_bytes_required")
    if len(source_bytes) > MAX_SOURCE_RECORD_BYTES:
        raise SourceRecordVerificationError("source_bytes_exceed_size_limit")

    expected = {
        "repository": expected_repository,
        "commit_sha": expected_commit_sha,
        "path": expected_path,
    }
    for field, value in expected.items():
        if not isinstance(value, str) or not value:
            raise SourceRecordVerificationError(f"expected_{field}_required")
        if record.get(field) != value:
            raise SourceRecordVerificationError(f"source_{field}_mismatch")

    commit_sha = record.get("commit_sha")
    blob_sha = record.get("git_blob_sha")
    if not isinstance(commit_sha, str) or not _SHA1_RE.fullmatch(commit_sha):
        raise SourceRecordVerificationError("source_commit_sha_invalid")
    if not isinstance(blob_sha, str) or not _SHA1_RE.fullmatch(blob_sha):
        raise SourceRecordVerificationError("source_git_blob_sha_invalid")

    start = record.get("start_line")
    end = record.get("end_line")
    if type(start) is not int or type(end) is not int or start < 1 or end < start:
        raise SourceRecordVerificationError("source_line_range_invalid")

    actual_blob_sha = _git_blob_sha1(source_bytes)
    if actual_blob_sha != blob_sha:
        raise SourceRecordVerificationError("source_git_blob_sha_mismatch")

    try:
        source_text = source_bytes.decode("utf-8")
        excerpt = record.get("excerpt")
        if not isinstance(excerpt, str) or not excerpt:
            raise SourceRecordVerificationError("source_excerpt_required")
        excerpt_bytes = excerpt.encode("utf-8")
    except UnicodeDecodeError as exc:
        raise SourceRecordVerificationError("source_bytes_not_utf8") from exc

    # Git text line coordinates are LF-delimited. Python str.splitlines() also
    # splits on bare CR and Unicode separators, which would shift Git line numbers.
    raw_lines = source_bytes.split(b"\n")
    lines = [part + b"\n" for part in raw_lines[:-1]]
    if raw_lines[-1]:
        lines.append(raw_lines[-1])
    if end > len(lines):
        raise SourceRecordVerificationError("source_line_range_out_of_bounds")
    actual_excerpt = b"".join(lines[start - 1:end])
    if actual_excerpt != excerpt_bytes:
        raise SourceRecordVerificationError("source_excerpt_mismatch")

    excerpt_sha256 = record.get("excerpt_sha256")
    actual_excerpt_sha256 = hashlib.sha256(actual_excerpt).hexdigest()
    if excerpt_sha256 != actual_excerpt_sha256:
        raise SourceRecordVerificationError("source_excerpt_sha256_mismatch")

    return {
        "valid": True,
        "repository": expected_repository,
        "commit_sha": expected_commit_sha,
        "path": expected_path,
        "git_blob_sha": actual_blob_sha,
        "excerpt_sha256": actual_excerpt_sha256,
        "start_line": start,
        "end_line": end,
        "provenance_verified": False,
    }
