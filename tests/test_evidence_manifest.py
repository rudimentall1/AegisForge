import pytest

from shared.evidence_manifest import EvidenceManifestError, build_manifest, digest, verify_manifest


def test_manifest_merkle_root_verifies():
    manifest = build_manifest([
        {"id": "a", "type": "claim", "digest": digest({"value": 1})},
        {"id": "b", "type": "claim", "digest": digest({"value": 2})},
        {"id": "c", "type": "claim", "digest": digest({"value": 3})},
    ])
    assert verify_manifest(manifest)["valid"] is True
    assert manifest["entry_count"] == 3


def test_manifest_tampering_changes_root():
    manifest = build_manifest([
        {"id": "a", "type": "claim", "digest": digest({"value": 1})},
        {"id": "b", "type": "claim", "digest": digest({"value": 2})},
    ])
    manifest["entries"][0]["digest"] = digest({"value": 99})
    with pytest.raises(EvidenceManifestError, match="manifest_root_mismatch"):
        verify_manifest(manifest)


from shared.evidence_manifest import build_source_record, source_excerpt_digest, validate_source_record


def source_record():
    return build_source_record(
        repository="johguse/profanity",
        commit_sha="0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6",
        path="Dispatcher.cpp", start_line=120, end_line=126,
        blob_sha="a" * 40, excerpt="synthetic excerpt for validation\\nsecond line",
    )


def test_source_record_hashes_exact_excerpt_and_states_limits():
    record = source_record()
    assert record["excerpt_sha256"] == source_excerpt_digest(record["excerpt"])
    validate_source_record(record)
    assert any("source authenticity" in item for item in record["limitations"])
    assert any("independent provenance" in item for item in record["limitations"])


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("commit_sha", "bad", "source_commit_sha_invalid"),
        ("git_blob_sha", "g" * 40, "source_git_blob_sha_invalid"),
        ("start_line", 0, "source_line_range_invalid"),
        ("end_line", 119, "source_line_range_invalid"),
        ("path", "../secrets", "source_path_invalid"),
        ("path", "..\\secrets", "source_path_invalid"),
        ("path", "C:\\secrets", "source_path_invalid"),
        ("path", "source//file.sol", "source_path_invalid"),
        ("repository", "not-a-repo", "source_repository_must_be_owner_repo"),
    ],
)
def test_source_record_rejects_malformed_coordinates(field, value, error):
    record = source_record()
    record[field] = value
    with pytest.raises(EvidenceManifestError, match=error):
        validate_source_record(record)


def test_source_record_detects_excerpt_tampering():
    record = source_record()
    record["excerpt"] += " tampered"
    with pytest.raises(EvidenceManifestError, match="source_excerpt_sha256_mismatch"):
        validate_source_record(record)


def test_source_record_rejects_hash_as_provenance_claim():
    record = source_record()
    record["limitations"] = ["Hash proves source authenticity and independent provenance."]
    with pytest.raises(EvidenceManifestError, match="source_limitations_must_distinguish_integrity_from_provenance"):
        validate_source_record(record)


def test_source_record_rejects_boolean_line_numbers():
    record = source_record()
    record["start_line"] = True
    with pytest.raises(EvidenceManifestError, match="source_line_range_invalid"):
        validate_source_record(record)
