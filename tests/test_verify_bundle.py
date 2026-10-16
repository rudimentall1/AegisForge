import hashlib
import json
import sqlite3
from dataclasses import asdict

import pytest

from shared.research_case import ResearchCase, research_case_binding
from shared.research_case_bundle import export_research_case_bundle
from shared.result_codec import encode
from shared.verify_bundle import (
    MANIFEST_FILENAME,
    MANIFEST_SCHEMA_VERSION,
    REPRODUCTION_CONTRACT_FILENAME,
    MAX_CONTRACT_BYTES,
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


def write_reproduction_bundle(root, *, malformed_contract=False):
    manifest, _ = write_bundle(root)
    contract = {
        "schema_version": "aegisforge-reproduction-contract-v1",
        "contract_id": "repro-contract-test-001",
        "case_id": "case-test-001",
        "hypothesis_id": "hypothesis-test-001",
        "target": {
            "repository": "owner/repository",
            "commit_sha": "a" * 40,
            "scope_reference": "https://example.com/security-scope",
            "source_path": "src/target.py",
        },
        "toolchain": {
            "runtime": "python",
            "version": "3.10.12",
            "image_ref": "python:3.10-slim@sha256:" + "b" * 64,
            "image_digest": "sha256:" + "b" * 64,
        },
        "command": ["python", "-m", "pytest", "-q"],
        "working_directory": ".",
        "environment": {"PYTHONHASHSEED": "0"},
        "network_access": "disabled",
        "limits": {
            "timeout_seconds": 10,
            "cpu_cores": 1,
            "memory_mb": 256,
            "max_processes": 16,
            "max_output_bytes": 1024 * 1024,
        },
        "expected_exit_code": 0,
        "expected_outputs": [{
            "path": "results/summary.json",
            "sha256": hashlib.sha256(b"expected").hexdigest(),
        }],
    }
    raw = b'{"schema_version": "bad"}' if malformed_contract else json.dumps(
        contract, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    contract_path = root / REPRODUCTION_CONTRACT_FILENAME
    contract_path.write_bytes(raw)
    manifest["artifacts"].append({
        "path": REPRODUCTION_CONTRACT_FILENAME,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
    })
    manifest["artifacts"].sort(key=lambda item: item["path"])
    rewrite_manifest(root, manifest)
    return contract


def test_level_one_passes_for_valid_bundle(tmp_path):
    write_bundle(tmp_path)

    result = verify_bundle(tmp_path, max_level=1)

    assert result["overall_status"] == "PASS"
    assert result["highest_completed_level"] == 1
    assert result["levels"][0]["status"] == "PASS"
    assert result["levels"][0]["checked_artifacts"] == 1


def test_unmanifested_file_fails_closed(tmp_path):
    write_bundle(tmp_path)
    (tmp_path / "untracked-evidence.txt").write_text("unverified bytes", encoding="utf-8")

    result = verify_bundle(tmp_path, max_level=1)

    assert result["overall_status"] == "FAIL"
    assert "unmanifested_bundle_file:untracked-evidence.txt" in result["levels"][0]["error"]


def test_unmanifested_empty_directory_fails_closed(tmp_path):
    write_bundle(tmp_path)
    (tmp_path / "untracked-empty-dir").mkdir()

    result = verify_bundle(tmp_path, max_level=1)

    assert result["overall_status"] == "FAIL"
    assert "unmanifested_bundle_directory:untracked-empty-dir" in result["levels"][0]["error"]


def test_unmanifested_symlink_directory_fails_closed(tmp_path):
    write_bundle(tmp_path)
    outside = tmp_path.parent / "outside-bundle-dir"
    outside.mkdir()
    (tmp_path / "escape").symlink_to(outside, target_is_directory=True)

    result = verify_bundle(tmp_path, max_level=1)

    assert result["overall_status"] == "FAIL"
    assert "bundle_directory_symlink_not_allowed:escape" in result["levels"][0]["error"]


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

    assert result["overall_status"] == "INCOMPLETE"
    assert result["highest_completed_level"] == 1
    assert [item["status"] for item in result["levels"]] == ["PASS", "INCONCLUSIVE"]
    assert result["levels"][0]["case_linkage_checked"] is True
    assert result["levels"][0]["task_count"] == 1


def test_research_case_zip_does_not_claim_experiment_rerun(tmp_path):
    bundle = _write_research_case_zip(tmp_path)

    result = verify_bundle(bundle)

    assert result["overall_status"] == "INCOMPLETE"
    assert [item["status"] for item in result["levels"]] == [
        "PASS", "INCONCLUSIVE", "NOT_RUN"
    ]



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



def test_zip_verifier_enforces_task_count_limit(tmp_path, monkeypatch):
    bundle = _write_research_case_zip(tmp_path)
    monkeypatch.setattr("shared.research_case_bundle.MAX_TASKS", 0)

    result = verify_bundle(bundle, max_level=1)

    assert result["overall_status"] == "FAIL"
    assert result["levels"][0]["error"] == "case_task_count_exceeds_limit"


def test_zip_verifier_enforces_evidence_count_limit(tmp_path, monkeypatch):
    bundle = _write_research_case_zip(tmp_path)
    monkeypatch.setattr("shared.research_case_bundle.MAX_EVIDENCE_ROWS", 0)

    result = verify_bundle(bundle, max_level=1)

    assert result["overall_status"] == "FAIL"
    assert result["levels"][0]["error"] == "case_evidence_count_exceeds_limit"



def test_standalone_verifier_bounds_reads_by_declared_artifact_size(tmp_path):
    manifest, _ = write_bundle(tmp_path)
    manifest["artifacts"][0]["size_bytes"] = 0
    rewrite_manifest(tmp_path, manifest)

    result = verify_bundle(tmp_path, max_level=1)

    assert result["overall_status"] == "FAIL"
    assert "artifact_size_mismatch" in result["levels"][0]["error"]


def test_zip_manifest_rejects_non_hex_member_digest(tmp_path):
    import zipfile

    bundle = _write_research_case_zip(tmp_path)
    rewritten = tmp_path / "malformed-digest.zip"
    with zipfile.ZipFile(bundle, "r") as source, zipfile.ZipFile(rewritten, "w") as target:
        for info in source.infolist():
            data = source.read(info.filename)
            if info.filename == "manifest.json":
                manifest = json.loads(data.decode("utf-8"))
                manifest["entries"][0]["sha256"] = "z" * 64
                core = {key: manifest[key] for key in ("schema_version", "case_id", "case_digest", "entries")}
                manifest["bundle_sha256"] = hashlib.sha256(
                    json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
                ).hexdigest()
                data = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            target.writestr(info, data)

    result = verify_bundle(rewritten, max_level=1)

    assert result["overall_status"] == "FAIL"
    assert result["levels"][0]["error"] == "manifest_member_digest_invalid"



def test_level_three_does_not_execute_by_default_even_when_contract_is_present(tmp_path, monkeypatch):
    write_reproduction_bundle(tmp_path)

    def unexpected_execution(*args, **kwargs):
        raise AssertionError("runner must not execute without explicit opt-in")

    monkeypatch.setattr("shared.verify_bundle.run_reproduction_contract", unexpected_execution)
    result = verify_bundle(tmp_path)

    assert result["levels"][2]["status"] == "NOT_RUN"
    assert result["levels"][2]["reason"] == "explicit_run_reproduction_required"


@pytest.mark.parametrize(
    "field,mismatched_value",
    [("case_id", "case-from-another-bundle"), ("hypothesis_id", "hypothesis-from-another-bundle")],
)
def test_level_three_rejects_contract_not_bound_to_manifest_case(
    tmp_path, monkeypatch, field, mismatched_value
):
    write_reproduction_bundle(tmp_path)
    manifest = json.loads((tmp_path / MANIFEST_FILENAME).read_text(encoding="utf-8"))
    contract_path = tmp_path / REPRODUCTION_CONTRACT_FILENAME
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    contract[field] = mismatched_value
    raw = json.dumps(contract, sort_keys=True, separators=(",", ":")).encode("utf-8")
    contract_path.write_bytes(raw)
    for artifact in manifest["artifacts"]:
        if artifact["path"] == REPRODUCTION_CONTRACT_FILENAME:
            artifact["sha256"] = hashlib.sha256(raw).hexdigest()
            artifact["size_bytes"] = len(raw)
    rewrite_manifest(tmp_path, manifest)

    def unexpected_execution(*args, **kwargs):
        raise AssertionError("mismatched case-bound contract must never execute")

    monkeypatch.setattr("shared.verify_bundle.run_reproduction_contract", unexpected_execution)
    result = verify_bundle(
        tmp_path,
        max_level=3,
        run_reproduction=True,
        target_checkout="/authorized/pinned/checkout",
        reproduction_output_dir="/tmp/aegisforge-reproduction-output",
    )

    assert result["levels"][2]["status"] == "FAIL"
    assert result["levels"][2]["reason"] == "reproduction_contract_case_binding_mismatch"
    assert "finding_verdict" not in result["levels"][2]
    assert result["overall_status"] == "INCOMPLETE"  # level 2 remains INCONCLUSIVE


def test_level_three_explicit_opt_in_runs_pinned_contract_and_never_changes_verdict(tmp_path, monkeypatch):
    write_reproduction_bundle(tmp_path)
    calls = []

    def fake_runner(contract, target_checkout, output_dir):
        calls.append((contract, target_checkout, output_dir))
        return {
            "status": "SUCCEEDED",
            "reason": None,
            "contract_sha256": "c" * 64,
            "exit_code": 0,
            "output_validation": {"status": "PASS"},
            "finding_verdict": "UNCHANGED",
        }

    monkeypatch.setattr("shared.verify_bundle.run_reproduction_contract", fake_runner)
    result = verify_bundle(
        tmp_path,
        max_level=3,
        run_reproduction=True,
        target_checkout="/authorized/pinned/checkout",
        reproduction_output_dir="/tmp/aegisforge-reproduction-output",
    )

    assert len(calls) == 1
    assert calls[0][1:] == (
        "/authorized/pinned/checkout",
        "/tmp/aegisforge-reproduction-output",
    )
    assert calls[0][0]["target"]["commit_sha"] == "a" * 40
    assert result["levels"][2]["status"] == "PASS"
    assert result["levels"][2]["finding_verdict"] == "UNCHANGED"
    assert result["highest_completed_level"] == 1
    assert result["overall_status"] == "INCOMPLETE"  # level 2 remains INCONCLUSIVE


def test_level_three_requires_explicit_target_and_output_paths(tmp_path, monkeypatch):
    write_reproduction_bundle(tmp_path)

    def unexpected_execution(*args, **kwargs):
        raise AssertionError("runner must not execute without explicit paths")

    monkeypatch.setattr("shared.verify_bundle.run_reproduction_contract", unexpected_execution)
    result = verify_bundle(tmp_path, run_reproduction=True)

    assert result["levels"][2]["status"] == "NOT_RUN"
    assert result["levels"][2]["reason"] == "target_checkout_and_output_dir_required"


def test_level_three_does_not_run_unmanifested_contract(tmp_path, monkeypatch):
    write_bundle(tmp_path)
    (tmp_path / REPRODUCTION_CONTRACT_FILENAME).write_text("{}", encoding="utf-8")

    def unexpected_execution(*args, **kwargs):
        raise AssertionError("unmanifested contract must never execute")

    monkeypatch.setattr("shared.verify_bundle.run_reproduction_contract", unexpected_execution)
    result = verify_bundle(
        tmp_path,
        run_reproduction=True,
        target_checkout="/authorized/pinned/checkout",
        reproduction_output_dir="/tmp/aegisforge-reproduction-output",
    )

    assert result["overall_status"] == "FAIL"
    assert result["levels"][0]["status"] == "FAIL"
    assert "unmanifested_bundle_file:reproduction-contract.json" in result["levels"][0]["error"]


def test_level_three_malformed_contract_fails_closed_without_execution(tmp_path, monkeypatch):
    write_reproduction_bundle(tmp_path, malformed_contract=True)

    def unexpected_execution(*args, **kwargs):
        raise AssertionError("malformed contract must never execute")

    monkeypatch.setattr("shared.verify_bundle.run_reproduction_contract", unexpected_execution)
    result = verify_bundle(
        tmp_path,
        run_reproduction=True,
        target_checkout="/authorized/pinned/checkout",
        reproduction_output_dir="/tmp/aegisforge-reproduction-output",
    )

    assert result["levels"][2]["status"] == "FAIL"
    assert result["levels"][2]["reason"] == "reproduction_contract_invalid"


def test_level_three_runner_failure_is_not_a_research_conclusion(tmp_path, monkeypatch):
    write_reproduction_bundle(tmp_path)
    monkeypatch.setattr(
        "shared.verify_bundle.run_reproduction_contract",
        lambda *args, **kwargs: {
            "status": "FAILED",
            "reason": "unexpected_exit_code",
            "contract_sha256": "c" * 64,
            "exit_code": 7,
        },
    )

    result = verify_bundle(
        tmp_path,
        run_reproduction=True,
        target_checkout="/authorized/pinned/checkout",
        reproduction_output_dir="/tmp/aegisforge-reproduction-output",
    )

    assert result["levels"][2]["status"] == "FAIL"
    assert result["levels"][2]["finding_verdict"] == "UNCHANGED"


@pytest.mark.parametrize(
    "runner_result,expected_reason",
    [
        (None, "reproduction_runner_result_invalid"),
        ({"status": []}, "reproduction_runner_status_invalid"),
        ({"status": "UNRECOGNIZED"}, "reproduction_runner_status_invalid"),
    ],
)
def test_level_three_malformed_runner_result_fails_closed(
    tmp_path, monkeypatch, runner_result, expected_reason
):
    write_reproduction_bundle(tmp_path)
    monkeypatch.setattr(
        "shared.verify_bundle.run_reproduction_contract",
        lambda *args, **kwargs: runner_result,
    )

    result = verify_bundle(
        tmp_path,
        run_reproduction=True,
        target_checkout="/authorized/pinned/checkout",
        reproduction_output_dir="/tmp/aegisforge-reproduction-output",
    )

    assert result["levels"][2]["status"] == "INCONCLUSIVE"
    assert result["levels"][2]["reason"] == expected_reason
    assert result["levels"][2]["finding_verdict"] == "UNCHANGED"


def test_level_three_timeout_is_inconclusive_not_rejected(tmp_path, monkeypatch):
    write_reproduction_bundle(tmp_path)
    monkeypatch.setattr(
        "shared.verify_bundle.run_reproduction_contract",
        lambda *args, **kwargs: {
            "status": "TIMED_OUT",
            "reason": "reproduction_timeout",
            "contract_sha256": "c" * 64,
        },
    )

    result = verify_bundle(
        tmp_path,
        run_reproduction=True,
        target_checkout="/authorized/pinned/checkout",
        reproduction_output_dir="/tmp/aegisforge-reproduction-output",
    )

    assert result["levels"][2]["status"] == "INCONCLUSIVE"
    assert result["levels"][2]["finding_verdict"] == "UNCHANGED"


def test_reproduction_opt_in_requires_level_three(tmp_path):
    write_bundle(tmp_path)
    with pytest.raises(ValueError, match="requires_max_level_3"):
        verify_bundle(tmp_path, max_level=1, run_reproduction=True)


@pytest.mark.parametrize("value", ["yes", 1, None])
def test_reproduction_opt_in_requires_strict_boolean(tmp_path, value):
    write_bundle(tmp_path)
    with pytest.raises(ValueError, match="must_be_boolean"):
        verify_bundle(tmp_path, run_reproduction=value)


def test_level_three_oversized_contract_fails_before_unbounded_read(tmp_path, monkeypatch):
    manifest, _ = write_bundle(tmp_path)
    raw = b" " * (MAX_CONTRACT_BYTES + 1)
    (tmp_path / REPRODUCTION_CONTRACT_FILENAME).write_bytes(raw)
    manifest["artifacts"].append({
        "path": REPRODUCTION_CONTRACT_FILENAME,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
    })
    manifest["artifacts"].sort(key=lambda item: item["path"])
    rewrite_manifest(tmp_path, manifest)

    def unexpected_execution(*args, **kwargs):
        raise AssertionError("oversized contract must never execute")

    monkeypatch.setattr("shared.verify_bundle.run_reproduction_contract", unexpected_execution)
    result = verify_bundle(
        tmp_path,
        run_reproduction=True,
        target_checkout="/authorized/pinned/checkout",
        reproduction_output_dir="/tmp/aegisforge-reproduction-output",
    )

    assert result["levels"][2]["status"] == "FAIL"
    assert result["levels"][2]["reason"] == "reproduction_contract_invalid"
    assert "contract_size_limit_exceeded" in result["levels"][2]["detail"]
