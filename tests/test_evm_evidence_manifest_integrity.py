import copy

import pytest

from tools.evm_key_forensics.evidence_manifest import (
    EvidenceManifestError,
    build_evidence_record,
    sha256_text,
    validate_evidence_record,
)


def sample_record():
    return build_evidence_record(
        repository="johguse/profanity",
        commit_sha="0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6",
        path="Dispatcher.cpp",
        start_line=120,
        end_line=126,
        blob_sha="a" * 40,
        excerpt="synthetic excerpt for validation\nsecond line",
    )


def test_builds_record_with_exact_excerpt_digest_and_scope_limits():
    record = sample_record()
    assert record["excerpt_sha256"] == sha256_text(record["excerpt"])
    assert record["limitations"]
    validate_evidence_record(record)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("commit_sha", "bad", "commit_sha_must_be_40_lowercase_hex"),
        ("git_blob_sha", "g" * 40, "git_blob_sha_must_be_40_lowercase_hex"),
        ("start_line", 0, "line_range_invalid"),
        ("end_line", 119, "line_range_invalid"),
        ("path", "../secrets", "path_must_be_relative_repository_path"),
        ("repository", "not-a-repo", "repository_must_be_owner_repo"),
    ],
)
def test_rejects_malformed_source_coordinates(field, value, message):
    record = copy.deepcopy(sample_record())
    record[field] = value
    with pytest.raises(EvidenceManifestError, match=message):
        validate_evidence_record(record)


def test_rejects_excerpt_tampering():
    record = copy.deepcopy(sample_record())
    record["excerpt"] += " tampered"
    with pytest.raises(EvidenceManifestError, match="excerpt_sha256_mismatch"):
        validate_evidence_record(record)


def test_rejects_claim_that_hash_proves_independent_origin():
    record = copy.deepcopy(sample_record())
    record["limitations"] = ["Hash proves source authenticity and independent provenance."]
    with pytest.raises(EvidenceManifestError, match="limitations_must_separate_hash_integrity_from_provenance"):
        validate_evidence_record(record)


def test_line_range_rejects_boolean_values():
    record = copy.deepcopy(sample_record())
    record["start_line"] = True
    with pytest.raises(EvidenceManifestError, match="line_range_invalid"):
        validate_evidence_record(record)
