import hashlib
import json
import sqlite3
from dataclasses import asdict

import pytest

from shared.research_case import ResearchCase, research_case_binding
from shared.research_case_bundle import export_research_case_bundle
from shared.result_codec import encode
from shared.verify_bundle import MANIFEST_FILENAME, MANIFEST_SCHEMA_VERSION, verify_bundle


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



def _write_research_case_zip(tmp_path):
    db_path = tmp_path / "case.db"
    bundle_path = tmp_path / "case.zip"
    case = ResearchCase(
        case_id="bundle-case-001",
        target_repository="example/protocol",
        target_commit="a" * 40,
        scope_url="https://example.com/security-scope",
        scope_digest="b" * 64,
        scope_reviewed_on="2026-10-16",
        hypothesis="A state transition may violate an accounting invariant.",
        attacker_capability="An unprivileged caller can invoke the public method.",
        expected_invariant="Recorded balance matches independent calculation.",
        falsification_criteria="Counter-tests preserve the invariant.",
        execution_mode="local",
        status="ready",
    )
    payload = asdict(case)
    payload["execution_mode"] = case.execution_mode.value
    payload["status"] = case.status.value
    result = {
        "stage": "validation",
        "research_case_binding": research_case_binding(case),
        "research_validation": {"historical_reproduction_confirmed": False},
    }
    with sqlite3.connect(db_path) as db:
        db.execute(
            "CREATE TABLE research_cases (case_id TEXT PRIMARY KEY, payload TEXT NOT NULL, registered_at TEXT NOT NULL)"
        )
        db.execute(
            """CREATE TABLE queue (
                id TEXT PRIMARY KEY, description TEXT NOT NULL, status TEXT NOT NULL,
                worker TEXT, created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
                role TEXT, parent_task_id TEXT, result BLOB, retry_count INTEGER,
                research_case_id TEXT, planner_decision TEXT
            )"""
        )
        db.execute(
            """CREATE TABLE evidence_observations (
                atom_id TEXT NOT NULL, task_id TEXT NOT NULL, role TEXT,
                observed_at TEXT NOT NULL, case_id TEXT
            )"""
        )
        db.execute(
            "CREATE TABLE evidence_ledger (atom_id TEXT PRIMARY KEY, kind TEXT, value TEXT)"
        )
        db.execute(
            "INSERT INTO research_cases VALUES (?, ?, ?)",
            (case.case_id, json.dumps(payload, sort_keys=True, separators=(",", ":")), "2026-10-16T00:00:00+00:00"),
        )
        db.execute(
            "INSERT INTO queue VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "task-001", "Validate pinned source", "completed", "validator-1",
                "2026-10-16T00:01:00+00:00", "2026-10-16T00:01:01+00:00",
                "2026-10-16T00:01:02+00:00", "validator", None,
                encode(result), 0, case.case_id, "COMPLETE",
            ),
        )
        db.execute(
            "INSERT INTO evidence_ledger VALUES (?, ?, ?)",
            ("atom-001", "finding", "synthetic counter-test recorded"),
        )
        db.execute(
            "INSERT INTO evidence_observations VALUES (?, ?, ?, ?, ?)",
            ("atom-001", "task-001", "validator", "2026-10-16T00:01:02+00:00", case.case_id),
        )
    export_research_case_bundle(db_path, case.case_id, bundle_path)
    return bundle_path


def test_research_case_zip_bundle_checks_integrity_and_case_linkage(tmp_path):
    bundle = _write_research_case_zip(tmp_path)

    result = verify_bundle(bundle, max_level=2)

    assert result["overall_status"] == "PASS"
    assert result["highest_completed_level"] == 2
    assert [item["status"] for item in result["levels"]] == ["PASS", "PASS"]
    assert result["levels"][1]["task_count"] == 1


def test_research_case_zip_does_not_claim_experiment_rerun(tmp_path):
    bundle = _write_research_case_zip(tmp_path)

    result = verify_bundle(bundle)

    assert result["overall_status"] == "INCOMPLETE"
    assert [item["status"] for item in result["levels"]] == [
        "PASS", "PASS", "NOT_RUN"
    ]
