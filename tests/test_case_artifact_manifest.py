import hashlib
import json
import pytest

from shared.evidence_ledger import (
    CASE_ARTIFACT_MANIFEST_FILENAME,
    CASE_ARTIFACT_MANIFEST_VERSION,
    MAX_CASE_ARTIFACTS,
    CaseArtifactManifestError,
    build_case_artifact_manifest,
    verify_case_artifact_manifest,
    write_case_artifact_manifest,
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


@pytest.mark.parametrize("path", ["../outside.txt", "/tmp/outside.txt", "logs\\run.txt", "C:/outside.txt", "logs/./run.txt", "logs//run.txt"])
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


def test_manifest_builder_rejects_duplicate_artifact_paths(tmp_path):
    write_artifact(tmp_path)
    with pytest.raises(CaseArtifactManifestError, match="duplicate_artifact_path"):
        build_case_artifact_manifest(
            tmp_path,
            case_id="case-2026-001",
            hypothesis_id="hypothesis-entropy-001",
            artifact_paths=["logs/run.txt", "logs/run.txt"],
        )


def test_manifest_verifier_rejects_unknown_fields(tmp_path):
    write_artifact(tmp_path)
    manifest = build(tmp_path)
    manifest["status"] = "PASS"

    result = verify_case_artifact_manifest(tmp_path, manifest)

    assert result == {"status": "FAIL", "errors": ["manifest_fields_invalid"]}



def test_manifest_writer_creates_bundle_manifest_accepted_by_independent_verifier(tmp_path):
    from shared.verify_bundle import verify_bundle

    write_artifact(tmp_path)
    manifest = write_case_artifact_manifest(
        tmp_path,
        case_id="case-2026-001",
        hypothesis_id="hypothesis-entropy-001",
        artifact_paths=["logs/run.txt"],
    )

    manifest_path = tmp_path / CASE_ARTIFACT_MANIFEST_FILENAME
    assert manifest_path.is_file()
    assert json.loads(manifest_path.read_text(encoding="utf-8")) == manifest
    result = verify_bundle(tmp_path, max_level=1)
    assert result["overall_status"] == "PASS"
    assert result["levels"][0]["checked_artifacts"] == 1


def test_manifest_writer_rejects_self_referential_artifact(tmp_path):
    write_artifact(tmp_path)
    with pytest.raises(
        CaseArtifactManifestError, match="manifest_cannot_include_itself_as_artifact"
    ):
        write_case_artifact_manifest(
            tmp_path,
            case_id="case-2026-001",
            hypothesis_id="hypothesis-entropy-001",
            artifact_paths=["logs/run.txt", CASE_ARTIFACT_MANIFEST_FILENAME],
        )


def test_manifest_writer_rejects_symlinked_manifest_destination(tmp_path):
    write_artifact(tmp_path)
    outside = tmp_path.parent / "existing-manifest.json"
    outside.write_text("{}", encoding="utf-8")
    (tmp_path / CASE_ARTIFACT_MANIFEST_FILENAME).symlink_to(outside)

    with pytest.raises(CaseArtifactManifestError, match="manifest_file_must_not_be_symlink"):
        write_case_artifact_manifest(
            tmp_path,
            case_id="case-2026-001",
            hypothesis_id="hypothesis-entropy-001",
            artifact_paths=["logs/run.txt"],
        )



def test_manifest_builder_rejects_self_reference_even_if_file_exists(tmp_path):
    write_artifact(tmp_path)
    write_artifact(
        tmp_path,
        relative_path=CASE_ARTIFACT_MANIFEST_FILENAME,
        content=b"stale manifest",
    )

    with pytest.raises(
        CaseArtifactManifestError, match="manifest_cannot_include_itself_as_artifact"
    ):
        build_case_artifact_manifest(
            tmp_path,
            case_id="case-2026-001",
            hypothesis_id="hypothesis-entropy-001",
            artifact_paths=["logs/run.txt", CASE_ARTIFACT_MANIFEST_FILENAME],
        )



def test_manifest_builder_rejects_symlinked_root(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    write_artifact(actual)
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)

    with pytest.raises(CaseArtifactManifestError, match="artifact_root_must_not_be_symlink"):
        build_case_artifact_manifest(
            alias,
            case_id="case-2026-001",
            hypothesis_id="hypothesis-entropy-001",
            artifact_paths=["logs/run.txt"],
        )



def test_manifest_builder_rejects_artifact_count_over_limit(tmp_path):
    with pytest.raises(CaseArtifactManifestError, match="artifact_count_limit_exceeded"):
        build_case_artifact_manifest(
            tmp_path,
            case_id="case-2026-001",
            hypothesis_id="hypothesis-entropy-001",
            artifact_paths=["missing.bin"] * (MAX_CASE_ARTIFACTS + 1),
        )


def test_manifest_builder_rejects_file_over_size_limit(tmp_path, monkeypatch):
    write_artifact(tmp_path, content=b"three")
    monkeypatch.setattr("shared.evidence_ledger.MAX_CASE_ARTIFACT_BYTES", 2)

    with pytest.raises(CaseArtifactManifestError, match="artifact_size_limit_exceeded"):
        build_case_artifact_manifest(
            tmp_path,
            case_id="case-2026-001",
            hypothesis_id="hypothesis-entropy-001",
            artifact_paths=["logs/run.txt"],
        )


def test_manifest_builder_rejects_total_size_over_limit(tmp_path, monkeypatch):
    write_artifact(tmp_path, "logs/one.txt", b"12")
    write_artifact(tmp_path, "logs/two.txt", b"34")
    monkeypatch.setattr("shared.evidence_ledger.MAX_CASE_ARTIFACT_TOTAL_BYTES", 3)

    with pytest.raises(CaseArtifactManifestError, match="bundle_size_limit_exceeded"):
        build_case_artifact_manifest(
            tmp_path,
            case_id="case-2026-001",
            hypothesis_id="hypothesis-entropy-001",
            artifact_paths=["logs/one.txt", "logs/two.txt"],
        )


def test_manifest_verifier_enforces_artifact_count_limit(tmp_path, monkeypatch):
    write_artifact(tmp_path)
    manifest = build(tmp_path)
    monkeypatch.setattr("shared.evidence_ledger.MAX_CASE_ARTIFACTS", 0)

    result = verify_case_artifact_manifest(tmp_path, manifest)

    assert result == {"status": "FAIL", "errors": ["artifact_count_limit_exceeded"]}


def test_manifest_verifier_enforces_file_size_limit(tmp_path, monkeypatch):
    write_artifact(tmp_path)
    manifest = build(tmp_path)
    monkeypatch.setattr("shared.evidence_ledger.MAX_CASE_ARTIFACT_BYTES", 1)

    result = verify_case_artifact_manifest(tmp_path, manifest)

    assert result["status"] == "FAIL"
    assert "artifact_size_limit_exceeded" in result["errors"][0]


def test_manifest_verifier_enforces_total_size_limit(tmp_path, monkeypatch):
    write_artifact(tmp_path)
    manifest = build(tmp_path)
    monkeypatch.setattr("shared.evidence_ledger.MAX_CASE_ARTIFACT_TOTAL_BYTES", 1)

    result = verify_case_artifact_manifest(tmp_path, manifest)

    assert result == {"status": "FAIL", "errors": ["bundle_size_limit_exceeded"]}
