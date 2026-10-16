import hashlib
import json
import sqlite3
import zipfile
from dataclasses import asdict, replace

import pytest

from shared.research_case import ResearchCase, research_case_binding
from shared.research_case_bundle import (
    ResearchCaseBundleError,
    export_research_case_bundle,
    verify_research_case_bundle,
)
from shared.result_codec import encode


def _case():
    return ResearchCase(
        case_id="bundle-case-001",
        target_repository="example/protocol",
        target_commit="a" * 40,
        scope_url="https://example.com/security-scope",
        scope_digest="b" * 64,
        scope_reviewed_on="2026-10-16",
        hypothesis="A state transition may violate an accounting invariant.",
        attacker_capability="An unprivileged caller can invoke the public method.",
        expected_invariant="The recorded balance matches the independently calculated balance.",
        falsification_criteria="Counter-tests preserve the invariant.",
        execution_mode="local",
        status="ready",
    )


def _database(path):
    case = _case()
    payload = asdict(case)
    payload["execution_mode"] = case.execution_mode.value
    payload["status"] = case.status.value
    binding = research_case_binding(case)
    result = {
        "stage": "validation",
        "research_case_binding": binding,
        "research_validation": {"historical_reproduction_confirmed": False},
    }
    with sqlite3.connect(path) as db:
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
                "task-001", "Validate the pinned source", "completed", "validator-1",
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
    return case


def test_case_bundle_export_is_portable_and_deterministic(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    first = tmp_path / "case-a.zip"
    second = tmp_path / "case-b.zip"

    report = export_research_case_bundle(db_path, case.case_id, first)
    second_report = export_research_case_bundle(db_path, case.case_id, second)

    assert report["valid"] is True
    assert report["case_id"] == case.case_id
    assert report["task_count"] == 1
    assert report["task_status_counts"] == {"completed": 1}
    assert report["evidence_observation_count"] == 1
    assert report["authenticity"] == "UNSIGNED_INTEGRITY_ONLY"
    assert first.read_bytes() == second.read_bytes()
    assert verify_research_case_bundle(first) == report


def test_case_bundle_accepts_historical_binding_after_case_status_changes(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)

    # The registered case currently says READY, but the completed task keeps
    # the valid snapshot from when it ran under RUNNING status.
    historical_case = replace(case, status="running")
    result = {
        "stage": "validation",
        "research_case_binding": research_case_binding(historical_case),
        "research_validation": {"historical_reproduction_confirmed": False},
    }
    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE queue SET result = ? WHERE id = ?",
            (encode(result), "task-001"),
        )

    bundle = tmp_path / "historical-status.zip"
    report = export_research_case_bundle(db_path, case.case_id, bundle)

    assert report["valid"] is True
    assert verify_research_case_bundle(bundle) == report


def test_case_bundle_rejects_unknown_historical_status_even_with_recomputed_digest(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)

    payload = asdict(case)
    payload["execution_mode"] = case.execution_mode.value
    payload["status"] = "unrecognized-status"
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    forged_binding = {
        "schema_version": "aegisforge-research-case-binding-v1",
        "case_id": case.case_id,
        "case_digest": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "case": payload,
    }
    result = {
        "stage": "validation",
        "research_case_binding": forged_binding,
        "research_validation": {"historical_reproduction_confirmed": False},
    }
    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE queue SET result = ? WHERE id = ?",
            (encode(result), "task-001"),
        )

    with pytest.raises(ResearchCaseBundleError, match="task_result_case_binding_invalid"):
        export_research_case_bundle(db_path, case.case_id, tmp_path / "invalid-status.zip")


def test_case_bundle_export_fails_for_unknown_case(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    _database(db_path)

    with pytest.raises(ResearchCaseBundleError, match="research_case_not_registered"):
        export_research_case_bundle(db_path, "missing-case", tmp_path / "missing.zip")


def test_case_bundle_verifier_rejects_tampered_member(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    bundle = tmp_path / "case.zip"
    export_research_case_bundle(db_path, case.case_id, bundle)

    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(bundle, "r") as source, zipfile.ZipFile(tampered, "w") as target:
        for item in source.infolist():
            raw = source.read(item.filename)
            if item.filename == "tasks.json":
                raw += b" "
            target.writestr(item, raw)

    with pytest.raises(ResearchCaseBundleError, match="bundle_member_digest_mismatch:tasks.json"):
        verify_research_case_bundle(tampered)


def test_case_bundle_verifier_rejects_path_traversal_member(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    bundle = tmp_path / "case.zip"
    export_research_case_bundle(db_path, case.case_id, bundle)

    changed = tmp_path / "path-traversal.zip"
    with zipfile.ZipFile(bundle, "r") as source, zipfile.ZipFile(changed, "w") as target:
        for item in source.infolist():
            name = "../" + item.filename if item.filename == "tasks.json" else item.filename
            target.writestr(name, source.read(item.filename))

    with pytest.raises(ResearchCaseBundleError, match="bundle_member_set_invalid"):
        verify_research_case_bundle(changed)


def test_case_bundle_export_rejects_evidence_linked_to_unknown_task(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE evidence_observations SET task_id = ? WHERE atom_id = ?",
            ("task-outside-case", "atom-001"),
        )

    with pytest.raises(
        ResearchCaseBundleError,
        match="evidence_observation_task_not_in_case_bundle",
    ):
        export_research_case_bundle(db_path, case.case_id, tmp_path / "orphaned.zip")


def test_case_bundle_verifier_rejects_integrity_valid_orphaned_observation(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    bundle = tmp_path / "case.zip"
    export_research_case_bundle(db_path, case.case_id, bundle)

    files = {}
    with zipfile.ZipFile(bundle, "r") as source:
        for name in source.namelist():
            files[name] = source.read(name)

    evidence = json.loads(files["evidence.json"])
    evidence["observations"][0]["task_id"] = "task-outside-case"
    files["evidence.json"] = json.dumps(
        evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

    manifest = json.loads(files["manifest.json"])
    entries = [
        {
            "path": name,
            "sha256": hashlib.sha256(files[name]).hexdigest(),
            "size": len(files[name]),
        }
        for name in sorted(("case.json", "tasks.json", "evidence.json"))
    ]
    core = {
        "schema_version": manifest["schema_version"],
        "case_id": manifest["case_id"],
        "case_digest": manifest["case_digest"],
        "entries": entries,
    }
    manifest = dict(core)
    manifest["bundle_sha256"] = hashlib.sha256(
        json.dumps(
            core, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    files["manifest.json"] = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

    forged = tmp_path / "integrity-valid-orphaned.zip"
    with zipfile.ZipFile(forged, "w", compression=zipfile.ZIP_DEFLATED) as target:
        for name in sorted(files):
            target.writestr(name, files[name])

    with pytest.raises(
        ResearchCaseBundleError,
        match="evidence_observation_task_not_in_case_bundle",
    ):
        verify_research_case_bundle(forged)


def test_case_bundle_export_rejects_parent_task_outside_case(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE queue SET parent_task_id = ? WHERE id = ?",
            ("task-from-another-case", "task-001"),
        )

    with pytest.raises(
        ResearchCaseBundleError,
        match="task_parent_not_in_case_bundle",
    ):
        export_research_case_bundle(
            db_path, case.case_id, tmp_path / "invalid-parent.zip"
        )


def test_case_bundle_verifier_rejects_parent_missing_from_bundle_even_with_rebuilt_manifest(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    bundle = tmp_path / "case.zip"
    export_research_case_bundle(db_path, case.case_id, bundle)

    with zipfile.ZipFile(bundle, "r") as source:
        files = {name: source.read(name) for name in source.namelist()}

    tasks = json.loads(files["tasks.json"])
    tasks["tasks"][0]["parent_task_id"] = "task-from-another-case"
    files["tasks.json"] = json.dumps(
        tasks, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

    manifest = json.loads(files["manifest.json"])
    manifest["entries"] = [
        {
            "path": name,
            "sha256": hashlib.sha256(files[name]).hexdigest(),
            "size": len(files[name]),
        }
        for name in sorted(("case.json", "tasks.json", "evidence.json"))
    ]
    core = {
        key: manifest[key]
        for key in ("schema_version", "case_id", "case_digest", "entries")
    }
    manifest["bundle_sha256"] = hashlib.sha256(
        json.dumps(
            core, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    files["manifest.json"] = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

    forged_bundle = tmp_path / "rebuilt-manifest.zip"
    with zipfile.ZipFile(forged_bundle, "w", compression=zipfile.ZIP_DEFLATED) as target:
        for name, raw in files.items():
            target.writestr(name, raw)

    with pytest.raises(
        ResearchCaseBundleError,
        match="task_parent_not_in_case_bundle",
    ):
        verify_research_case_bundle(forged_bundle)
