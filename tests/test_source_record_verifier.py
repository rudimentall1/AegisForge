import hashlib

import pytest

from shared.source_record_verifier import (
    SourceRecordVerificationError,
    verify_source_record_against_bytes,
)


REPOSITORY = "example/source"
COMMIT = "0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6"
PATH = "src/example.py"
SOURCE = b"first line\nsecond line\nthird line\n"


def git_blob_sha(content):
    return hashlib.sha1(b"blob " + str(len(content)).encode("ascii") + b"\0" + content).hexdigest()


def record_for(source=SOURCE):
    excerpt = "second line\n"
    return {
        "repository": REPOSITORY,
        "commit_sha": COMMIT,
        "path": PATH,
        "start_line": 2,
        "end_line": 2,
        "git_blob_sha": git_blob_sha(source),
        "excerpt_sha256": hashlib.sha256(excerpt.encode("utf-8")).hexdigest(),
        "excerpt": excerpt,
        "limitations": [
            "Hashes establish byte identity, not source authenticity.",
            "This record does not establish independent provenance.",
        ],
    }


def verify(record=None, source=SOURCE, **expected):
    return verify_source_record_against_bytes(
        record or record_for(source),
        source,
        expected_repository=expected.get("repository", REPOSITORY),
        expected_commit_sha=expected.get("commit_sha", COMMIT),
        expected_path=expected.get("path", PATH),
    )


def test_verifies_exact_source_blob_and_inclusive_line_range():
    result = verify()
    assert result["valid"] is True
    assert result["git_blob_sha"] == git_blob_sha(SOURCE)
    assert result["provenance_verified"] is False


@pytest.mark.parametrize(
    ("field", "expected", "error"),
    [
        ("repository", "someone/else", "source_repository_mismatch"),
        ("commit_sha", "1" * 40, "source_commit_sha_mismatch"),
        ("path", "src/other.py", "source_path_mismatch"),
    ],
)
def test_rejects_coordinate_mismatch(field, expected, error):
    with pytest.raises(SourceRecordVerificationError, match=error):
        verify(**{field: expected})


def test_rejects_modified_source_bytes():
    with pytest.raises(SourceRecordVerificationError, match="source_git_blob_sha_mismatch"):
        verify(source=SOURCE + b"modified\n")


def test_rejects_excerpt_that_does_not_match_selected_lines():
    record = record_for()
    record["excerpt"] = "third line\n"
    record["excerpt_sha256"] = hashlib.sha256(record["excerpt"].encode()).hexdigest()
    with pytest.raises(SourceRecordVerificationError, match="source_excerpt_mismatch"):
        verify(record=record)


def test_rejects_out_of_bounds_line_range():
    record = record_for()
    record["end_line"] = 99
    with pytest.raises(SourceRecordVerificationError, match="source_line_range_out_of_bounds"):
        verify(record=record)


def test_preserves_crlf_and_missing_final_newline():
    source = b"alpha\r\nbeta"
    excerpt = "beta"
    record = {
        "repository": REPOSITORY,
        "commit_sha": COMMIT,
        "path": PATH,
        "start_line": 2,
        "end_line": 2,
        "git_blob_sha": git_blob_sha(source),
        "excerpt_sha256": hashlib.sha256(excerpt.encode()).hexdigest(),
        "excerpt": excerpt,
        "limitations": ["No source authenticity or independent provenance claim."],
    }
    result = verify_source_record_against_bytes(
        record, source, expected_repository=REPOSITORY,
        expected_commit_sha=COMMIT, expected_path=PATH,
    )
    assert result["valid"] is True


def test_rejects_non_byte_source():
    with pytest.raises(SourceRecordVerificationError, match="source_bytes_required"):
        verify_source_record_against_bytes(
            record_for(), "not bytes", expected_repository=REPOSITORY,
            expected_commit_sha=COMMIT, expected_path=PATH,
        )
