import hashlib
import json

import pytest

from shared.verify_bundle import (
    MANIFEST_FILENAME,
    MANIFEST_SCHEMA_VERSION,
    MAX_ARTIFACTS,
    MAX_ARTIFACT_BYTES,
    MAX_MANIFEST_BYTES,
    verify_bundle,
)


def write_bundle(root, *, content=b"evidence bytes"):
    artifact = root / "logs" / "run.txt"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_bytes(content)
    artifacts = [{
        "path": "logs/run.txt",
        "sha256": hashlib.sha256(content).hexdigest(),
        "size_bytes": len(content),
    }]
    payload = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "case_id": "case-test-001",
        "hypothesis_id": "hypothesis-test-001",
        "artifacts": artifacts,
    }
    payload["manifest_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    (root / MANIFEST_FILENAME).write_text(json.dumps(payload), encoding="utf-8")
    return payload, artifact


def rewrite_manifest(root, manifest):
    payload = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    manifest["manifest_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    (root / MANIFEST_FILENAME).write_text(json.dumps(manifest), encoding="utf-8")


def test_level_one_passes_for_valid_bundle(tmp_path):
    write_bundle(tmp_path)

    result = verify_bundle(tmp_path, max_level=1)

    assert result["overall_status"] == "PASS"
    assert result["highest_completed_level"] == 1
    assert result["levels"][0]["status"] == "PASS"
    assert result["levels"][0]["checked_artifacts"] == 1


def test_default_levels_do_not_overclaim_provenance_or_rerun(tmp_path):
    write_bundle(tmp_path)

    result = verify_bundle(tmp_path)

    assert result["overall_status"] == "INCOMPLETE"
    assert [item["status"] for item in result["levels"]] == [
        "PASS", "INCONCLUSIVE", "NOT_RUN"
    ]
    assert "authenticity" not in result


def test_one_byte_tampering_fails_integrity(tmp_path):
    _, artifact = write_bundle(tmp_path)
    artifact.write_bytes(b"evidence byteS")

    result = verify_bundle(tmp_path, max_level=1)

    assert result["overall_status"] == "FAIL"
    assert "artifact_digest_mismatch:logs/run.txt" in result["levels"][0]["error"]


@pytest.mark.parametrize("bad_path", [
    "../outside.txt", "/tmp/outside.txt", "logs\\run.txt", "C:/outside.txt",
    "logs/./run.txt", "logs//run.txt",
])
def test_invalid_path_fails_closed(tmp_path, bad_path):
    manifest, _ = write_bundle(tmp_path)
    manifest["artifacts"][0]["path"] = bad_path
    rewrite_manifest(tmp_path, manifest)

    result = verify_bundle(tmp_path, max_level=1)

    assert result["overall_status"] == "FAIL"
    assert result["levels"][0]["status"] == "FAIL"


def test_duplicate_json_keys_fail_closed(tmp_path):
    write_bundle(tmp_path)
    (tmp_path / MANIFEST_FILENAME).write_text(
        '{"schema_version":"aegisforge-case-artifact-manifest-v1",'
        '"schema_version":"aegisforge-case-artifact-manifest-v1"}',
        encoding="utf-8",
    )

    result = verify_bundle(tmp_path, max_level=1)

    assert result["overall_status"] == "FAIL"
    assert "duplicate_json_key" in result["levels"][0]["error"]


@pytest.mark.parametrize("bad_size", [True, -1, "13"])
def test_malformed_nonempty_size_fails_closed(tmp_path, bad_size):
    manifest, _ = write_bundle(tmp_path)
    manifest["artifacts"][0]["size_bytes"] = bad_size
    rewrite_manifest(tmp_path, manifest)

    result = verify_bundle(tmp_path, max_level=1)

    assert result["overall_status"] == "FAIL"
    assert result["levels"][0]["status"] == "FAIL"


def test_manifest_digest_mismatch_fails_closed(tmp_path):
    manifest, _ = write_bundle(tmp_path)
    manifest["case_id"] = "case-tampered"
    (tmp_path / MANIFEST_FILENAME).write_text(json.dumps(manifest), encoding="utf-8")

    result = verify_bundle(tmp_path, max_level=1)

    assert result["overall_status"] == "FAIL"
    assert "manifest_digest_mismatch" in result["levels"][0]["error"]


def test_missing_manifest_fails_closed(tmp_path):
    result = verify_bundle(tmp_path, max_level=1)

    assert result["overall_status"] == "FAIL"
    assert "manifest_missing" in result["levels"][0]["error"]


def test_symlinked_artifact_is_rejected(tmp_path):
    manifest, artifact = write_bundle(tmp_path)
    outside = tmp_path.parent / "outside-evidence.txt"
    outside.write_bytes(artifact.read_bytes())
    artifact.unlink()
    artifact.symlink_to(outside)

    result = verify_bundle(tmp_path, max_level=1)

    assert result["overall_status"] == "FAIL"
    assert "symlink" in result["levels"][0]["error"]


def test_symlinked_bundle_root_is_rejected(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    write_bundle(actual)
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)

    result = verify_bundle(alias, max_level=1)

    assert result["overall_status"] == "FAIL"
    assert "root_must_not_be_symlink" in result["levels"][0]["error"]


def test_invalid_max_level_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="max_level_must_be_1_2_or_3"):
        verify_bundle(tmp_path, max_level=True)



def test_artifact_size_limit_fails_before_opening_large_file(tmp_path):
    manifest, _ = write_bundle(tmp_path)
    manifest["artifacts"][0]["size_bytes"] = MAX_ARTIFACT_BYTES + 1
    rewrite_manifest(tmp_path, manifest)

    result = verify_bundle(tmp_path, max_level=1)

    assert result["overall_status"] == "FAIL"
    assert "artifact_size_limit_exceeded" in result["levels"][0]["error"]


def test_total_bundle_size_limit_fails_before_reading_artifacts(tmp_path):
    manifest, _ = write_bundle(tmp_path)
    manifest["artifacts"] = [
        {
            "path": f"artifact-{index}.bin",
            "sha256": "0" * 64,
            "size_bytes": MAX_ARTIFACT_BYTES,
        }
        for index in range(5)
    ]
    rewrite_manifest(tmp_path, manifest)

    result = verify_bundle(tmp_path, max_level=1)

    assert result["overall_status"] == "FAIL"
    assert "bundle_size_limit_exceeded" in result["levels"][0]["error"]


def test_artifact_count_limit_fails_closed(tmp_path):
    manifest, _ = write_bundle(tmp_path)
    manifest["artifacts"] = [
        {
            "path": f"artifact-{index}.bin",
            "sha256": "0" * 64,
            "size_bytes": 0,
        }
        for index in range(MAX_ARTIFACTS + 1)
    ]
    rewrite_manifest(tmp_path, manifest)

    result = verify_bundle(tmp_path, max_level=1)

    assert result["overall_status"] == "FAIL"
    assert "manifest_artifact_count_limit_exceeded" in result["levels"][0]["error"]


def test_manifest_size_limit_fails_closed(tmp_path):
    (tmp_path / MANIFEST_FILENAME).write_bytes(b" " * (MAX_MANIFEST_BYTES + 1))

    result = verify_bundle(tmp_path, max_level=1)

    assert result["overall_status"] == "FAIL"
    assert "manifest_size_limit_exceeded" in result["levels"][0]["error"]


def test_nonstandard_json_constant_fails_closed(tmp_path):
    write_bundle(tmp_path)
    (tmp_path / MANIFEST_FILENAME).write_text('{"value": NaN}', encoding="utf-8")

    result = verify_bundle(tmp_path, max_level=1)

    assert result["overall_status"] == "FAIL"
    assert "nonstandard_json_constant" in result["levels"][0]["error"]
