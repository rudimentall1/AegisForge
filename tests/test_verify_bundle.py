import json

import pytest

from shared.evidence_ledger import build_case_artifact_manifest
from shared.verify_bundle import verify_bundle


def make_bundle(root):
    artifact = root / "logs" / "run.txt"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_bytes(b"synthetic evidence\x00")
    manifest = build_case_artifact_manifest(
        root,
        case_id="case-test-001",
        hypothesis_id="hypothesis-test-001",
        artifact_paths=["logs/run.txt"],
    )
    (root / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True), encoding="utf-8"
    )
    return manifest


def test_directory_bundle_checks_integrity_but_does_not_claim_provenance_or_rerun(tmp_path):
    make_bundle(tmp_path)

    result = verify_bundle(tmp_path)

    assert result["verification_levels"][0]["status"] == "PASS"
    assert result["verification_levels"][1]["status"] == "INCONCLUSIVE"
    assert result["verification_levels"][2]["status"] == "INCONCLUSIVE"
    assert "No bundle-controlled command is executed." in result["limitations"]


def test_one_byte_artifact_tampering_fails_level_one(tmp_path):
    make_bundle(tmp_path)
    (tmp_path / "logs" / "run.txt").write_bytes(b"synthetic evidence!")

    result = verify_bundle(tmp_path)

    assert result["valid"] is False
    assert result["verification_levels"][0]["status"] == "FAIL"
    assert "artifact_digest_mismatch" in result["verification_levels"][0]["detail"]


@pytest.mark.parametrize(
    "bad_digest",
    ["z" * 64, "a" * 63, "A" * 64, " " * 64],
)
def test_malformed_nonempty_artifact_digest_fails_closed(tmp_path, bad_digest):
    manifest = make_bundle(tmp_path)
    manifest["artifacts"][0]["sha256"] = bad_digest
    (tmp_path / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True), encoding="utf-8"
    )

    result = verify_bundle(tmp_path)

    assert result["valid"] is False
    assert result["verification_levels"][0]["status"] == "FAIL"


def test_duplicate_json_keys_are_rejected(tmp_path):
    (tmp_path / "manifest.json").write_text(
        '{"schema_version":"x","schema_version":"y"}', encoding="utf-8"
    )

    result = verify_bundle(tmp_path)

    assert result["valid"] is False
    assert result["verification_levels"][0]["status"] == "FAIL"
    assert "duplicate_json_key" in result["verification_levels"][0]["detail"]


def test_unsupported_file_format_fails_closed(tmp_path):
    path = tmp_path / "not-a-bundle.bin"
    path.write_bytes(b"not a bundle")

    result = verify_bundle(path)

    assert result["valid"] is False
    assert result["verification_levels"][0]["status"] == "FAIL"
