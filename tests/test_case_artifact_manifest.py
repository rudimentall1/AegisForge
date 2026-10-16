import hashlib
import json

import pytest

from shared.evidence_ledger import (
    CASE_ARTIFACT_MANIFEST_VERSION,
    CaseArtifactManifestError,
    build_case_artifact_manifest,
    verify_case_artifact_manifest,
)


def write_artifact(root, relative_path="logs/run.txt", content=b"original evidence\x00bytes"):
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def build(root, paths=("logs/run.txt",)):
    return build_case_artifact_manifest(
        root,
        case_id="case-2026-001",
        hypothesis_id="hypothesis-entropy-001",
        artifact_paths=list(paths),
    )


def test_case_manifest_binds_artifact_bytes_to_case_and_hypothesis(tmp_path):
    write_artifact(tmp_path)
    manifest = build(tmp_path)

    result = verify_case_artifact_manifest(tmp_path, manifest)

    assert manifest["schema_version"] == CASE_ARTIFACT_MANIFEST_VERSION
    assert manifest["case_id"] == "case-2026-001"
    assert manifest["hypothesis_id"] == "hypothesis-entropy-001"
    assert manifest["artifacts"][0]["sha256"] == hashlib.sha256(
        b"original evidence\x00bytes"
    ).hexdigest()
    assert result["status"] == "PASS"
    assert result["checked_artifacts"] == 1


def test_one_byte_tampering_is_detected(tmp_path):
    path = write_artifact(tmp_path)
    manifest = build(tmp_path)
    path.write_bytes(b"original evidence\x00byteS")

    result = verify_case_artifact_manifest(tmp_path, manifest)

    assert result["status"] == "FAIL"
    assert "artifact_digest_mismatch:logs/run.txt" in result["errors"][0]


def test_missing_artifact_fails_closed(tmp_path):
    write_artifact(tmp_path)
    manifest = build(tmp_path)
    (tmp_path / "logs/run.txt").unlink()

    result = verify_case_artifact_manifest(tmp_path, manifest)

    assert result["status"] == "FAIL"
    assert result["errors"][0].startswith("artifact_unavailable:logs/run.txt:")


@pytest.mark.parametrize("case_id", ["", "   ", None, 7])
def test_manifest_builder_rejects_missing_or_malformed_case_id(tmp_path, case_id):
    write_artifact(tmp_path)
    with pytest.raises(CaseArtifactManifestError, match="invalid_case_id"):
        build_case_artifact_manifest(
            tmp_path,
            case_id=case_id,
            hypothesis_id="hypothesis-entropy-001",
            artifact_paths=["logs/run.txt"],
        )


@pytest.mark.parametrize("path", ["../outside.txt", "/tmp/outside.txt", "logs\\run.txt", "C:/outside.txt"])
def test_manifest_builder_rejects_malformed_nonempty_artifact_paths(tmp_path, path):
    write_artifact(tmp_path)
    with pytest.raises(CaseArtifactManifestError, match="invalid_artifact_path"):
        build_case_artifact_manifest(
            tmp_path,
            case_id="case-2026-001",
            hypothesis_id="hypothesis-entropy-001",
            artifact_paths=[path],
        )


def test_manifest_verifier_rejects_malformed_nonempty_digest(tmp_path):
    write_artifact(tmp_path)
    manifest = build(tmp_path)
    manifest["artifacts"][0]["sha256"] = "z" * 64

    result = verify_case_artifact_manifest(tmp_path, manifest)

    assert result == {"status": "FAIL", "errors": ["artifact_digest_invalid:logs/run.txt"]}


def test_manifest_verifier_rejects_tampered_manifest_digest(tmp_path):
    write_artifact(tmp_path)
    manifest = build(tmp_path)
    manifest["case_id"] = "case-2026-002"

    result = verify_case_artifact_manifest(tmp_path, manifest)

    assert result == {"status": "FAIL", "errors": ["manifest_digest_mismatch"]}


def test_manifest_verifier_rejects_duplicate_artifact_paths(tmp_path):
    write_artifact(tmp_path)
    manifest = build_case_artifact_manifest(
        tmp_path,
        case_id="case-2026-001",
        hypothesis_id="hypothesis-entropy-001",
        artifact_paths=["logs/run.txt", "logs/run.txt"],
    )

    # Builder rejects duplicates before creating an ambiguous manifest.
    assert manifest["artifacts"] == [
        {
            "path": "logs/run.txt",
            "sha256": hashlib.sha256(b"original evidence\\x00bytes").hexdigest(),
            "size_bytes": len(b"original evidence\\x00bytes"),
        }
    ]


def test_manifest_verifier_rejects_unknown_fields(tmp_path):
    write_artifact(tmp_path)
    manifest = build(tmp_path)
    manifest["status"] = "PASS"

    result = verify_case_artifact_manifest(tmp_path, manifest)

    assert result == {"status": "FAIL", "errors": ["manifest_fields_invalid"]}
