import hashlib
import json
import sqlite3
import zipfile
from dataclasses import asdict, replace

import pytest

from shared.research_case import ResearchCase, RoundSpec, research_case_binding
from shared.research_case_bundle import (
    ResearchCaseBundleError,
    export_research_case_bundle,
    verify_research_case_bundle,
    main as research_case_bundle_main,
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
                research_case_id TEXT, planner_decision TEXT, round_id TEXT
            )"""
        )
        db.execute(
            """CREATE TABLE evidence_observations (
                atom_id TEXT NOT NULL, task_id TEXT NOT NULL, role TEXT,
                observed_at TEXT NOT NULL, case_id TEXT, round_id TEXT
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
            "INSERT INTO queue VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "task-001", "Validate the pinned source", "completed", "validator-1",
                "2026-10-16T00:01:00+00:00", "2026-10-16T00:01:01+00:00",
                "2026-10-16T00:01:02+00:00", "validator", None,
                encode(result), 0, case.case_id, "COMPLETE", None,
            ),
        )
        db.execute(
            "INSERT INTO evidence_ledger VALUES (?, ?, ?)",
            ("atom-001", "finding", "synthetic counter-test recorded"),
        )
        db.execute(
            "INSERT INTO evidence_observations VALUES (?, ?, ?, ?, ?, ?)",
            ("atom-001", "task-001", "validator", "2026-10-16T00:01:02+00:00", case.case_id, None),
        )
    return case


def _merkle_root(entries):
    if not entries:
        return hashlib.sha256(b"aegisforge:research-case-bundle:merkle-empty:v1\0").hexdigest()
    level = [hashlib.sha256(
        b"aegisforge:research-case-bundle:merkle-leaf:v1\0"
        + json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    ).digest() for entry in entries]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(
            b"aegisforge:research-case-bundle:merkle-node:v1\0" + level[i] + level[i + 1]
        ).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


def _refresh_manifest(files, manifest):
    manifest["merkle_root"] = _merkle_root(manifest["entries"])
    core = {key: manifest[key] for key in ("schema_version", "case_id", "case_digest", "entries", "merkle_root")}
    manifest["bundle_sha256"] = hashlib.sha256(
        json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    ).hexdigest()
    files["manifest.json"] = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _rewrite_bundle_json_member(bundle, output, member_name, mutate):
    """Rebuild an unsigned manifest after a deliberate fixture mutation."""
    with zipfile.ZipFile(bundle, "r") as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    payload = json.loads(files[member_name])
    mutate(payload)
    files[member_name] = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    manifest = json.loads(files["manifest.json"])
    manifest["entries"] = [
        {"path": name, "sha256": hashlib.sha256(files[name]).hexdigest(), "size": len(files[name])}
        for name in sorted(files)
        if name != "manifest.json"
    ]
    _refresh_manifest(files, manifest)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(files):
            archive.writestr(name, files[name])


def _database_with_round_registry(path):
    case = _database(path)
    planned_case = replace(
        case,
        rounds=(
            RoundSpec(
                round_id="source-pattern-v1",
                technique="source_pattern",
                hypothesis="Check a pinned source pattern.",
                expected_evidence_atoms=("source-pattern-present",),
                falsification_criteria="Pinned source lacks the pattern.",
                priority=1,
                disclosure_deadline_days=30,
            ),
        ),
    )
    payload = asdict(planned_case)
    payload["execution_mode"] = planned_case.execution_mode.value
    payload["status"] = planned_case.status.value
    runtime_round_id = "a4eaf8b6-1f77-4c61-8b28-bb8d7bbf4a00"
    result = {
        "stage": "validation",
        "research_case_binding": research_case_binding(planned_case),
        "research_validation": {"historical_reproduction_confirmed": False},
    }
    with sqlite3.connect(path) as db:
        db.execute("ALTER TABLE queue ADD COLUMN round_spec_id TEXT")
        db.execute("ALTER TABLE evidence_observations ADD COLUMN round_spec_id TEXT")
        db.execute(
            "UPDATE research_cases SET payload = ? WHERE case_id = ?",
            (json.dumps(payload, sort_keys=True, separators=(",", ":")), case.case_id),
        )
        db.execute(
            "UPDATE queue SET result = ?, round_id = ?, round_spec_id = ?, role = ? WHERE id = ?",
            (encode(result), runtime_round_id, "source-pattern-v1", "source_researcher", "task-001"),
        )
        db.execute(
            "UPDATE evidence_observations SET round_id = ?, round_spec_id = ?, role = ? WHERE task_id = ?",
            (runtime_round_id, "source-pattern-v1", "source_researcher", "task-001"),
        )
        db.execute(
            """CREATE TABLE research_case_rounds (
                round_id TEXT PRIMARY KEY, case_id TEXT NOT NULL,
                round_number INTEGER NOT NULL, root_task_id TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL, round_spec_id TEXT, status TEXT NOT NULL,
                started_at TEXT, finished_at TEXT, UNIQUE(case_id, round_number)
            )"""
        )
        db.execute(
            "INSERT INTO research_case_rounds VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (runtime_round_id, case.case_id, 1, "task-001",
             "2026-10-16T00:01:00+00:00", "source-pattern-v1", "COMPLETED",
             "2026-10-16T00:01:01+00:00", "2026-10-16T00:01:02+00:00"),
        )
    return case, runtime_round_id


def test_case_bundle_exports_and_verifies_runtime_round_registry(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case, runtime_round_id = _database_with_round_registry(db_path)
    bundle = tmp_path / "case-with-rounds.zip"
    export_research_case_bundle(db_path, case.case_id, bundle)
    with zipfile.ZipFile(bundle, "r") as archive:
        rounds = json.loads(archive.read("rounds.json"))
    assert rounds["registry_available"] is True
    assert rounds["rounds"][0]["round_id"] == runtime_round_id
    assert rounds["rounds"][0]["round_spec_id"] == "source-pattern-v1"
    report = verify_research_case_bundle(bundle)
    assert report["valid"] is True


def test_case_bundle_verifier_rejects_runtime_identity_collapsed_into_planned_identity(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case, _ = _database_with_round_registry(db_path)
    original = tmp_path / "case-with-rounds.zip"
    forged = tmp_path / "collapsed-round-identities.zip"
    export_research_case_bundle(db_path, case.case_id, original)

    def collapse_round_identities(payload):
        planned_id = "source-pattern-v1"
        payload["rounds"][0]["round_id"] = planned_id

    _rewrite_bundle_json_member(original, forged, "rounds.json", collapse_round_identities)
    # Keep the archive internally linked and recompute all hashes: the verifier
    # must reject the semantic identity collapse, not merely a stale manifest.
    def align_task_ids(payload):
        for task in payload["tasks"]:
            if task.get("round_spec_id") == "source-pattern-v1":
                task["round_id"] = "source-pattern-v1"

    aligned_tasks = tmp_path / "collapsed-round-identities-tasks.zip"
    _rewrite_bundle_json_member(forged, aligned_tasks, "tasks.json", align_task_ids)

    def align_evidence_ids(payload):
        for observation in payload["observations"]:
            if observation.get("round_spec_id") == "source-pattern-v1":
                observation["round_id"] = "source-pattern-v1"

    _rewrite_bundle_json_member(
        aligned_tasks, forged, "evidence.json", align_evidence_ids
    )
    with pytest.raises(
        ResearchCaseBundleError,
        match="round_registry_runtime_matches_spec_identity",
    ):
        verify_research_case_bundle(forged)


def test_case_bundle_export_rejects_runtime_round_missing_from_registry(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case, _ = _database_with_round_registry(db_path)
    orphan_runtime_id = "b5fbcf26-234f-4c20-8e58-4dce06e7d5bb"
    with sqlite3.connect(db_path) as db:
        db.execute(
            """INSERT INTO queue
               (id, description, status, created_at, role, parent_task_id,
                result, retry_count, research_case_id, planner_decision,
                round_id, round_spec_id)
               VALUES (?, ?, 'pending', ?, 'validator', ?, NULL, 0, ?, NULL, ?, ?)""",
            ("child-task-orphan-round", "Synthetic child with unregistered round",
             "2026-10-16T00:02:00+00:00", "task-001", case.case_id,
             orphan_runtime_id, "source-pattern-v1"),
        )
    with pytest.raises(ResearchCaseBundleError, match="task_runtime_round_missing_from_registry"):
        export_research_case_bundle(db_path, case.case_id, tmp_path / "orphan-round.zip")


def test_case_bundle_export_rejects_child_task_with_different_planned_round(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case, runtime_round_id = _database_with_round_registry(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute(
            """INSERT INTO queue
               (id, description, status, created_at, role, parent_task_id,
                result, retry_count, research_case_id, planner_decision,
                round_id, round_spec_id)
               VALUES (?, ?, 'pending', ?, 'validator', ?, NULL, 0, ?, NULL, ?, ?)""",
            ("child-task-wrong-spec", "Synthetic child with mismatched planned round",
             "2026-10-16T00:02:00+00:00", "task-001", case.case_id,
             runtime_round_id, None),
        )

    with pytest.raises(
        ResearchCaseBundleError,
        match="task_parent_round_spec_identity_mismatch",
    ):
        export_research_case_bundle(
            db_path, case.case_id, tmp_path / "mismatched-child-spec.zip"
        )


def test_case_bundle_export_rejects_runtime_ids_without_round_registry(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case, _ = _database_with_round_registry(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute("DROP TABLE research_case_rounds")

    with pytest.raises(
        ResearchCaseBundleError,
        match="round_registry_unavailable_with_runtime_ids",
    ):
        export_research_case_bundle(
            db_path, case.case_id, tmp_path / "unlinked-runtime-round.zip"
        )


def test_case_bundle_verifier_rejects_duplicate_runtime_round_numbers(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case, _ = _database_with_round_registry(db_path)
    original = tmp_path / "case-with-rounds.zip"
    with_duplicate_task = tmp_path / "duplicate-round-task.zip"
    forged = tmp_path / "duplicate-round-number.zip"
    export_research_case_bundle(db_path, case.case_id, original)

    def add_second_root(payload):
        root = dict(payload["tasks"][0])
        root.update({
            "id": "task-002",
            "description": "Synthetic second round root",
            "status": "pending",
            "parent_task_id": None,
            "round_id": "c6b6dca7-b87f-45a0-81d7-52dfc5e9b69f",
        })
        payload["tasks"].append(root)

    _rewrite_bundle_json_member(original, with_duplicate_task, "tasks.json", add_second_root)

    def add_duplicate_number(payload):
        second = dict(payload["rounds"][0])
        second.update({
            "round_id": "c6b6dca7-b87f-45a0-81d7-52dfc5e9b69f",
            "root_task_id": "task-002",
        })
        payload["rounds"].append(second)

    _rewrite_bundle_json_member(
        with_duplicate_task, forged, "rounds.json", add_duplicate_number
    )
    with pytest.raises(
        ResearchCaseBundleError, match="round_registry_number_duplicate"
    ):
        verify_research_case_bundle(forged)


def test_case_bundle_verifier_rejects_runtime_ids_when_registry_unavailable(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case, _ = _database_with_round_registry(db_path)
    original = tmp_path / "case-with-rounds.zip"
    forged = tmp_path / "unavailable-registry-runtime-ids.zip"
    export_research_case_bundle(db_path, case.case_id, original)

    def hide_registry(payload):
        payload.update({"registry_available": False, "rounds": []})

    _rewrite_bundle_json_member(original, forged, "rounds.json", hide_registry)
    with pytest.raises(
        ResearchCaseBundleError,
        match="round_registry_unavailable_with_runtime_ids",
    ):
        verify_research_case_bundle(forged)


def test_case_bundle_verifier_rejects_records_when_round_registry_marked_unavailable(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case, _ = _database_with_round_registry(db_path)
    original = tmp_path / "case-with-rounds.zip"
    forged = tmp_path / "unavailable-registry-with-records.zip"
    export_research_case_bundle(db_path, case.case_id, original)
    _rewrite_bundle_json_member(
        original,
        forged,
        "rounds.json",
        lambda payload: payload.update({"registry_available": False}),
    )

    with pytest.raises(
        ResearchCaseBundleError,
        match="round_registry_unavailable_but_records_present",
    ):
        verify_research_case_bundle(forged)


def test_case_bundle_verifier_rejects_forged_round_root_even_with_rebuilt_manifest(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case, _ = _database_with_round_registry(db_path)
    original = tmp_path / "case-with-rounds.zip"
    forged = tmp_path / "forged-round-registry.zip"
    export_research_case_bundle(db_path, case.case_id, original)
    _rewrite_bundle_json_member(
        original,
        forged,
        "rounds.json",
        lambda payload: payload["rounds"][0].update({"root_task_id": "missing-root-task"}),
    )
    with pytest.raises(ResearchCaseBundleError, match="round_registry_root_task_missing"):
        verify_research_case_bundle(forged)


def test_case_bundle_verifier_rejects_unknown_task_fields_even_when_manifest_is_rebuilt(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    original = tmp_path / "case.zip"
    forged = tmp_path / "forged-task.zip"
    export_research_case_bundle(db_path, case.case_id, original)
    _rewrite_bundle_json_member(original, forged, "tasks.json", lambda p: p["tasks"][0].update({"agent_claimed_authority": "verified"}))
    with pytest.raises(ResearchCaseBundleError, match="task_record_unexpected_fields"):
        verify_research_case_bundle(forged)


def test_case_bundle_verifier_rejects_unknown_evidence_fields_even_when_manifest_is_rebuilt(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    original = tmp_path / "case.zip"
    forged = tmp_path / "forged-evidence.zip"
    export_research_case_bundle(db_path, case.case_id, original)
    _rewrite_bundle_json_member(original, forged, "evidence.json", lambda p: p["observations"][0].update({"review_status": "independently_confirmed"}))
    with pytest.raises(ResearchCaseBundleError, match="evidence_record_unexpected_fields"):
        verify_research_case_bundle(forged)


def test_case_bundle_rejects_evidence_role_mismatch(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE evidence_observations SET role = ? WHERE task_id = ?",
            ("source_researcher", "task-001"),
        )

    with pytest.raises(ResearchCaseBundleError, match="evidence_observation_role_mismatch"):
        export_research_case_bundle(db_path, case.case_id, tmp_path / "role-mismatch.zip")


def test_case_bundle_accepts_runtime_round_id_distinct_from_declared_spec(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    planned_case = replace(
        case,
        rounds=(
            RoundSpec(
                round_id="declared-round",
                technique="source_pattern",
                hypothesis="Check the pinned source for a specific pattern.",
                expected_evidence_atoms=("source-pattern-present",),
                falsification_criteria="Pinned source lacks the pattern.",
                priority=1,
                disclosure_deadline_days=30,
            ),
        ),
    )
    payload = asdict(planned_case)
    payload["execution_mode"] = planned_case.execution_mode.value
    payload["status"] = planned_case.status.value
    binding = research_case_binding(planned_case)
    result = {
        "stage": "validation",
        "research_case_binding": binding,
        "research_validation": {"historical_reproduction_confirmed": False},
    }
    runtime_round_id = "a4eaf8b6-1f77-4c61-8b28-bb8d7bbf4a00"
    with sqlite3.connect(db_path) as db:
        db.execute("ALTER TABLE queue ADD COLUMN round_spec_id TEXT")
        db.execute("ALTER TABLE evidence_observations ADD COLUMN round_spec_id TEXT")
        db.execute(
            "UPDATE research_cases SET payload = ? WHERE case_id = ?",
            (json.dumps(payload, sort_keys=True, separators=(",", ":")), case.case_id),
        )
        db.execute(
            "UPDATE queue SET result = ?, round_id = ?, round_spec_id = ? WHERE id = ?",
            (encode(result), runtime_round_id, "declared-round", "task-001"),
        )
        db.execute(
            "UPDATE evidence_observations SET round_id = ?, round_spec_id = ? WHERE task_id = ?",
            (runtime_round_id, "declared-round", "task-001"),
        )

    bundle = tmp_path / "runtime-round.zip"
    report = export_research_case_bundle(db_path, case.case_id, bundle)
    assert report["valid"] is True
    with zipfile.ZipFile(bundle, "r") as archive:
        tasks = json.loads(archive.read("tasks.json"))["tasks"]
        observations = json.loads(archive.read("evidence.json"))["observations"]
    assert tasks[0]["round_id"] == runtime_round_id
    assert tasks[0]["round_spec_id"] == "declared-round"
    assert observations[0]["round_id"] == runtime_round_id
    assert observations[0]["round_spec_id"] == "declared-round"
    assert verify_research_case_bundle(bundle)["valid"] is True


def test_case_bundle_verifier_rejects_forged_evidence_role_even_with_rebuilt_manifest(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    original = tmp_path / "case.zip"
    forged = tmp_path / "forged-role.zip"
    export_research_case_bundle(db_path, case.case_id, original)
    _rewrite_bundle_json_member(
        original,
        forged,
        "evidence.json",
        lambda p: p["observations"][0].update({"role": "source_researcher"}),
    )
    with pytest.raises(ResearchCaseBundleError, match="evidence_observation_role_mismatch"):
        verify_research_case_bundle(forged)


def test_case_bundle_export_rejects_planned_identity_without_runtime_round(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case, _ = _database_with_round_registry(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute("UPDATE queue SET round_id = NULL WHERE id = ?", ("task-001",))

    with pytest.raises(
        ResearchCaseBundleError, match="task_round_spec_requires_runtime_round"
    ):
        export_research_case_bundle(db_path, case.case_id, tmp_path / "invalid.zip")


def test_case_bundle_verifier_rejects_planned_identity_without_runtime_round(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case, _ = _database_with_round_registry(db_path)
    original = tmp_path / "case-with-rounds.zip"
    forged = tmp_path / "planned-without-runtime-round.zip"
    export_research_case_bundle(db_path, case.case_id, original)

    def add_unbound_planned_task(payload):
        payload["tasks"].append({
            "id": "task-unbound-planned",
            "description": "Synthetic task with a plan but no execution round",
            "status": "pending",
            "created_at": "2026-10-16T00:02:00+00:00",
            "result": None,
            "research_case_id": case.case_id,
            "role": "crypto_analyst",
            "parent_task_id": None,
            "round_id": None,
            "round_spec_id": "source-pattern-v1",
        })

    _rewrite_bundle_json_member(original, forged, "tasks.json", add_unbound_planned_task)
    with pytest.raises(
        ResearchCaseBundleError, match="task_round_spec_requires_runtime_round"
    ):
        verify_research_case_bundle(forged)


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


def test_case_bundle_export_rejects_completed_non_object_result_before_writing(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE queue SET result = ? WHERE id = ?",
            (encode("legacy completed result"), "task-001"),
        )

    output = tmp_path / "case-invalid.zip"
    with pytest.raises(
        ResearchCaseBundleError,
        match="completed_task_missing_case_binding",
    ):
        export_research_case_bundle(db_path, case.case_id, output)

    assert not output.exists()


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
    manifest["entries"] = entries
    _refresh_manifest(files, manifest)
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
    _refresh_manifest(files, manifest)

    forged_bundle = tmp_path / "rebuilt-manifest.zip"
    with zipfile.ZipFile(forged_bundle, "w", compression=zipfile.ZIP_DEFLATED) as target:
        for name, raw in files.items():
            target.writestr(name, raw)

    with pytest.raises(
        ResearchCaseBundleError,
        match="task_parent_not_in_case_bundle",
    ):
        verify_research_case_bundle(forged_bundle)


def test_case_bundle_verifier_rejects_parent_cycle_even_with_rebuilt_manifest(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    bundle = tmp_path / "case.zip"
    export_research_case_bundle(db_path, case.case_id, bundle)

    with zipfile.ZipFile(bundle, "r") as source:
        files = {name: source.read(name) for name in source.namelist()}

    tasks = json.loads(files["tasks.json"])
    tasks["tasks"][0]["parent_task_id"] = tasks["tasks"][0]["id"]
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
    _refresh_manifest(files, manifest)

    forged_bundle = tmp_path / "rebuilt-manifest.zip"
    with zipfile.ZipFile(forged_bundle, "w", compression=zipfile.ZIP_DEFLATED) as target:
        for name, raw in files.items():
            target.writestr(name, raw)

    with pytest.raises(
        ResearchCaseBundleError,
        match="task_parent_cycle_detected",
    ):
        verify_research_case_bundle(forged_bundle)


def test_case_bundle_verifier_rejects_non_string_parent_even_with_rebuilt_manifest(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    bundle = tmp_path / "case.zip"
    export_research_case_bundle(db_path, case.case_id, bundle)

    with zipfile.ZipFile(bundle, "r") as source:
        files = {name: source.read(name) for name in source.namelist()}

    tasks = json.loads(files["tasks.json"])
    tasks["tasks"][0]["parent_task_id"] = []
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
    _refresh_manifest(files, manifest)

    forged_bundle = tmp_path / "rebuilt-manifest.zip"
    with zipfile.ZipFile(forged_bundle, "w", compression=zipfile.ZIP_DEFLATED) as target:
        for name, raw in files.items():
            target.writestr(name, raw)

    with pytest.raises(
        ResearchCaseBundleError,
        match="task_parent_identity_invalid",
    ):
        verify_research_case_bundle(forged_bundle)

def test_case_bundle_export_rejects_multi_task_parent_cycle(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)

    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE queue SET parent_task_id = ? WHERE id = ?",
            ("task-002", "task-001"),
        )
        db.execute(
            "INSERT INTO queue VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "task-002", "Child task in a cyclic chain", "queued", None,
                "2026-10-16T00:02:00+00:00", None, None, "validator",
                "task-001", None, 0, case.case_id, "CONTINUE", None,
            ),
        )

    with pytest.raises(
        ResearchCaseBundleError,
        match="task_parent_cycle_detected",
    ):
        export_research_case_bundle(
            db_path, case.case_id, tmp_path / "cyclic-lineage.zip"
        )


def test_case_bundle_export_rejects_observation_without_ledger_record(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute("DELETE FROM evidence_ledger WHERE atom_id = ?", ("atom-001",))

    with pytest.raises(
        ResearchCaseBundleError,
        match="evidence_observation_ledger_entry_missing",
    ):
        export_research_case_bundle(
            db_path, case.case_id, tmp_path / "orphaned-ledger-entry.zip"
        )



def test_case_bundle_preserves_round_identity_in_tasks_and_evidence(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute("UPDATE queue SET round_id = ? WHERE id = ?", ("round-1", "task-001"))
        db.execute(
            "UPDATE evidence_observations SET round_id = ? WHERE task_id = ?",
            ("round-1", "task-001"),
        )

    bundle = tmp_path / "round-bound.zip"
    report = export_research_case_bundle(db_path, case.case_id, bundle)
    with zipfile.ZipFile(bundle, "r") as archive:
        tasks = json.loads(archive.read("tasks.json"))["tasks"]
        observations = json.loads(archive.read("evidence.json"))["observations"]

    assert report["valid"] is True
    assert tasks[0]["round_id"] == "round-1"
    assert observations[0]["round_id"] == "round-1"
    assert verify_research_case_bundle(bundle) == report


def test_case_bundle_export_rejects_conflicting_evidence_round_identity(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute("UPDATE queue SET round_id = ? WHERE id = ?", ("round-1", "task-001"))
        db.execute(
            "UPDATE evidence_observations SET round_id = ? WHERE task_id = ?",
            ("round-2", "task-001"),
        )

    with pytest.raises(
        ResearchCaseBundleError,
        match="evidence_observation_round_identity_mismatch",
    ):
        export_research_case_bundle(db_path, case.case_id, tmp_path / "conflicting-round.zip")


def test_case_bundle_rejects_changed_round_plan_in_historical_binding(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    changed_round_plan = replace(
        case,
        rounds=(
            RoundSpec(
                round_id="round-plan-altered",
                technique="source_pattern",
                hypothesis="A changed round hypothesis",
                expected_evidence_atoms=("source-pattern-present",),
                falsification_criteria="Pinned source lacks the pattern",
                priority=1,
                disclosure_deadline_days=30,
            ),
        ),
    )
    result = {
        "stage": "validation",
        "research_case_binding": research_case_binding(changed_round_plan),
        "research_validation": {"historical_reproduction_confirmed": False},
    }
    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE queue SET result = ? WHERE id = ?",
            (encode(result), "task-001"),
        )

    with pytest.raises(
        ResearchCaseBundleError,
        match="task_result_case_binding_mismatch",
    ):
        export_research_case_bundle(
            db_path, case.case_id, tmp_path / "altered-round-plan.zip"
        )


def test_case_bundle_export_rejects_evidence_missing_task_round_identity(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute("UPDATE queue SET round_id = ? WHERE id = ?", ("round-001", "task-001"))

    with pytest.raises(
        ResearchCaseBundleError,
        match="evidence_observation_round_identity_mismatch",
    ):
        export_research_case_bundle(db_path, case.case_id, tmp_path / "missing-round.zip")


def test_case_bundle_verifier_rejects_integrity_valid_missing_evidence_round_identity(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute("UPDATE queue SET round_id = ? WHERE id = ?", ("round-001", "task-001"))
        db.execute("UPDATE evidence_observations SET round_id = ? WHERE atom_id = ?", ("round-001", "atom-001"))
    bundle = tmp_path / "case.zip"
    export_research_case_bundle(db_path, case.case_id, bundle)

    files = {}
    with zipfile.ZipFile(bundle, "r") as source:
        files = {name: source.read(name) for name in source.namelist()}
    evidence = json.loads(files["evidence.json"])
    evidence["observations"][0]["round_id"] = None
    files["evidence.json"] = json.dumps(
        evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    manifest = json.loads(files["manifest.json"])
    manifest["entries"] = [
        {"path": name, "sha256": hashlib.sha256(files[name]).hexdigest(), "size": len(files[name])}
        for name in sorted(("case.json", "tasks.json", "evidence.json"))
    ]
    _refresh_manifest(files, manifest)
    forged = tmp_path / "integrity-valid-missing-round.zip"
    with zipfile.ZipFile(forged, "w", compression=zipfile.ZIP_DEFLATED) as target:
        for name in sorted(files):
            target.writestr(name, files[name])

    with pytest.raises(
        ResearchCaseBundleError,
        match="evidence_observation_round_identity_mismatch",
    ):
        verify_research_case_bundle(forged)


def test_case_bundle_export_rejects_child_task_from_different_round(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute("UPDATE queue SET round_id = ? WHERE id = ?", ("round-001", "task-001"))
        db.execute(
            """INSERT INTO queue
               (id, description, status, created_at, role, parent_task_id,
                result, retry_count, research_case_id, round_id)
               VALUES (?, ?, 'pending', ?, 'crypto_analyst', ?, NULL, 0, ?, ?)""",
            ("task-002", "child task", "2026-10-16T00:02:00+00:00", "task-001", case.case_id, "round-002"),
        )

    with pytest.raises(
        ResearchCaseBundleError,
        match="task_parent_round_identity_mismatch",
    ):
        export_research_case_bundle(db_path, case.case_id, tmp_path / "cross-round.zip")


def test_case_bundle_verifier_rejects_rehashed_cross_round_child(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute("UPDATE queue SET round_id = ? WHERE id = ?", ("round-001", "task-001"))
        db.execute("UPDATE evidence_observations SET round_id = ? WHERE atom_id = ?", ("round-001", "atom-001"))
        db.execute(
            """INSERT INTO queue
               (id, description, status, created_at, role, parent_task_id,
                result, retry_count, research_case_id, round_id)
               VALUES (?, ?, 'pending', ?, 'crypto_analyst', ?, NULL, 0, ?, ?)""",
            ("task-002", "child task", "2026-10-16T00:02:00+00:00", "task-001", case.case_id, "round-001"),
        )
    original = tmp_path / "valid.zip"
    forged = tmp_path / "cross-round.zip"
    export_research_case_bundle(db_path, case.case_id, original)
    _rewrite_bundle_json_member(
        original,
        forged,
        "tasks.json",
        lambda payload: payload["tasks"][1].update({"round_id": "round-002"}),
    )

    with pytest.raises(
        ResearchCaseBundleError,
        match="task_parent_round_identity_mismatch",
    ):
        verify_research_case_bundle(forged)


def test_case_bundle_verifier_rejects_stale_merkle_root_after_entry_hashes_are_rebuilt(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    original = tmp_path / "original.zip"
    forged = tmp_path / "stale-merkle-root.zip"
    export_research_case_bundle(db_path, case.case_id, original)
    with zipfile.ZipFile(original, "r") as archive:
        files = {name: archive.read(name) for name in archive.namelist()}

    tasks = json.loads(files["tasks.json"])
    tasks["tasks"][0]["description"] = "Altered after export"
    files["tasks.json"] = json.dumps(
        tasks, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    manifest = json.loads(files["manifest.json"])
    original_root = manifest["merkle_root"]
    manifest["entries"] = [
        {"path": name, "sha256": hashlib.sha256(files[name]).hexdigest(), "size": len(files[name])}
        for name in sorted(("case.json", "tasks.json", "evidence.json"))
    ]
    # Rebuild the ordinary manifest digest but deliberately retain the old root.
    core = {
        key: manifest[key]
        for key in ("schema_version", "case_id", "case_digest", "entries", "merkle_root")
    }
    manifest["bundle_sha256"] = hashlib.sha256(
        json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    ).hexdigest()
    assert manifest["merkle_root"] == original_root
    files["manifest.json"] = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    with zipfile.ZipFile(forged, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(files):
            archive.writestr(name, files[name])

    with pytest.raises(ResearchCaseBundleError, match="bundle_merkle_root_mismatch"):
        verify_research_case_bundle(forged)


def test_case_bundle_verifier_keeps_schema_v1_compatibility(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    original = tmp_path / "v2.zip"
    legacy = tmp_path / "v1.zip"
    export_research_case_bundle(db_path, case.case_id, original)
    with zipfile.ZipFile(original, "r") as archive:
        files = {name: archive.read(name) for name in archive.namelist()}

    for name in ("tasks.json", "evidence.json"):
        payload = json.loads(files[name])
        payload["schema_version"] = "aegisforge-research-case-bundle-v1"
        collection = "tasks" if name == "tasks.json" else "observations"
        for record in payload[collection]:
            record.pop("round_spec_id", None)
        files[name] = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    manifest = json.loads(files["manifest.json"])
    manifest["schema_version"] = "aegisforge-research-case-bundle-v1"
    manifest.pop("merkle_root")
    manifest["entries"] = [
        {"path": name, "sha256": hashlib.sha256(files[name]).hexdigest(), "size": len(files[name])}
        for name in sorted(("case.json", "tasks.json", "evidence.json"))
    ]
    core = {key: manifest[key] for key in ("schema_version", "case_id", "case_digest", "entries")}
    manifest["bundle_sha256"] = hashlib.sha256(
        json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    ).hexdigest()
    files["manifest.json"] = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    # Schema v1 contains only the original three payloads plus manifest.
    files.pop("rounds.json", None)
    with zipfile.ZipFile(legacy, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(files):
            archive.writestr(name, files[name])

    report = verify_research_case_bundle(legacy)
    assert report["valid"] is True
    assert report["schema_version"] == "aegisforge-research-case-bundle-v1"


def test_case_bundle_verifier_keeps_schema_v2_compatibility(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    original = tmp_path / "v3.zip"
    legacy = tmp_path / "v2.zip"
    export_research_case_bundle(db_path, case.case_id, original)
    with zipfile.ZipFile(original, "r") as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    files.pop("rounds.json", None)
    for name in ("tasks.json", "evidence.json"):
        payload = json.loads(files[name])
        payload["schema_version"] = "aegisforge-research-case-bundle-v2"
        collection = "tasks" if name == "tasks.json" else "observations"
        for record in payload[collection]:
            record.pop("round_spec_id", None)
        files[name] = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    manifest = json.loads(files["manifest.json"])
    manifest["schema_version"] = "aegisforge-research-case-bundle-v2"
    manifest["entries"] = [
        {"path": name, "sha256": hashlib.sha256(files[name]).hexdigest(), "size": len(files[name])}
        for name in sorted(("case.json", "tasks.json", "evidence.json"))
    ]
    _refresh_manifest(files, manifest)
    with zipfile.ZipFile(legacy, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(files):
            archive.writestr(name, files[name])
    report = verify_research_case_bundle(legacy)
    assert report["valid"] is True
    assert report["schema_version"] == "aegisforge-research-case-bundle-v2"


def test_case_bundle_verifier_documents_unsigned_manifest_rewrite_boundary(tmp_path):
    """A recomputed unsigned manifest is not an authenticity guarantee."""
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    original = tmp_path / "original.zip"
    rewritten = tmp_path / "rewritten.zip"
    export_research_case_bundle(db_path, case.case_id, original)

    # This helper changes a member and recomputes its entry hash, Merkle root,
    # and bundle digest. Since the bundle has no trusted signature/anchor, the
    # verifier can establish internal consistency, not historical authenticity.
    _rewrite_bundle_json_member(
        original,
        rewritten,
        "tasks.json",
        lambda payload: payload["tasks"][0].update(description="Rewritten by an editor"),
    )

    report = verify_research_case_bundle(rewritten)
    assert report["valid"] is True
    assert report["schema_version"] == "aegisforge-research-case-bundle-v3"



def test_case_bundle_cli_verifies_offline_after_database_is_removed(tmp_path, capsys):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    bundle = tmp_path / "portable-case.zip"
    export_research_case_bundle(db_path, case.case_id, bundle)

    # The verification command must depend only on the portable ZIP, not on the
    # source database or the environment that created it.
    db_path.unlink()
    assert research_case_bundle_main(["verify", str(bundle)]) == 0
    report = json.loads(capsys.readouterr().out)

    assert report["valid"] is True
    assert report["case_id"] == case.case_id
    assert report["authenticity"] == "UNSIGNED_INTEGRITY_ONLY"


def test_case_bundle_verifier_rejects_rehashed_manifest_case_identity_mismatch(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    original = tmp_path / "original.zip"
    forged = tmp_path / "forged-manifest-case-id.zip"
    export_research_case_bundle(db_path, case.case_id, original)

    with zipfile.ZipFile(original, "r") as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    manifest = json.loads(files["manifest.json"])
    manifest["case_id"] = "different-case-id"
    _refresh_manifest(files, manifest)
    with zipfile.ZipFile(forged, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(files):
            archive.writestr(name, files[name])

    # All unsigned digests are valid after the mutation; rejection must come
    # from the case identity contract, not a stale hash.
    with pytest.raises(ResearchCaseBundleError, match="bundle_case_identity_mismatch"):
        verify_research_case_bundle(forged)



def test_case_bundle_verifier_rejects_rehashed_target_commit_mismatch(tmp_path):
    """Recomputed unsigned hashes must not hide a task bound to another source commit."""
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    original = tmp_path / "original.zip"
    forged = tmp_path / "rehashed-target-commit.zip"
    export_research_case_bundle(db_path, case.case_id, original)

    changed_case = replace(case, target_commit="c" * 40)

    def alter_task_binding(payload):
        payload["tasks"][0]["result"]["research_case_binding"] = research_case_binding(
            changed_case
        )

    _rewrite_bundle_json_member(original, forged, "tasks.json", alter_task_binding)

    # The manifest, entry hashes, Merkle root and bundle digest are internally
    # consistent. The verifier must reject the semantic source-commit mismatch.
    with pytest.raises(
        ResearchCaseBundleError,
        match="task_result_case_binding_mismatch",
    ):
        verify_research_case_bundle(forged)


def test_case_bundle_verifier_rejects_forged_case_source_commit_against_task_binding(tmp_path):
    """A rehashed case record cannot rewrite the source revision used by its task."""
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    original = tmp_path / "original.zip"
    forged = tmp_path / "forged-case-source-commit.zip"
    export_research_case_bundle(db_path, case.case_id, original)

    with zipfile.ZipFile(original, "r") as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    case_payload = json.loads(files["case.json"])
    binding = case_payload["research_case_binding"]
    changed_case = dict(binding["case"])
    changed_case["target_commit"] = "d" * 40
    canonical = json.dumps(
        changed_case,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    binding["case"] = changed_case
    binding["case_digest"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    files["case.json"] = json.dumps(
        case_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")

    manifest = json.loads(files["manifest.json"])
    # Update the manifest's case digest too, so the verifier reaches semantic
    # case/task comparison instead of rejecting a stale manifest reference.
    manifest["case_digest"] = binding["case_digest"]
    manifest["entries"] = [
        {"path": name, "sha256": hashlib.sha256(files[name]).hexdigest(), "size": len(files[name])}
        for name in sorted(("case.json", "tasks.json", "evidence.json"))
    ]
    _refresh_manifest(files, manifest)
    with zipfile.ZipFile(forged, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(files):
            archive.writestr(name, files[name])

    # All unsigned bundle hashes and case-digest references are consistent.
    # The completed task still records the original immutable case contract.
    with pytest.raises(
        ResearchCaseBundleError,
        match="task_result_case_binding_mismatch",
    ):
        verify_research_case_bundle(forged)



def test_case_bundle_export_rejects_undeclared_planned_round_identity(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute("ALTER TABLE queue ADD COLUMN round_spec_id TEXT")
        db.execute(
            "UPDATE queue SET round_spec_id = ? WHERE id = ?",
            ("undeclared-round", "task-001"),
        )

    with pytest.raises(
        ResearchCaseBundleError,
        match="task_round_spec_not_declared_in_case",
    ):
        export_research_case_bundle(
            db_path, case.case_id, tmp_path / "undeclared-round.zip"
        )


def test_case_bundle_export_rejects_evidence_planned_round_mismatch(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute("ALTER TABLE evidence_observations ADD COLUMN round_spec_id TEXT")
        db.execute(
            "UPDATE evidence_observations SET round_spec_id = ? WHERE atom_id = ?",
            ("unbound-round", "atom-001"),
        )

    with pytest.raises(
        ResearchCaseBundleError,
        match="evidence_observation_round_spec_identity_mismatch",
    ):
        export_research_case_bundle(
            db_path, case.case_id, tmp_path / "mismatched-round.zip"
        )


def test_case_bundle_verifier_rejects_undeclared_planned_round_identity(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    case = _database(db_path)
    original = tmp_path / "case.zip"
    forged = tmp_path / "forged-round-spec.zip"
    export_research_case_bundle(db_path, case.case_id, original)
    _rewrite_bundle_json_member(
        original,
        forged,
        "tasks.json",
        lambda payload: payload["tasks"][0].update(
            {"round_spec_id": "undeclared-round"}
        ),
    )
    with pytest.raises(
        ResearchCaseBundleError,
        match="task_round_spec_not_declared_in_case",
    ):
        verify_research_case_bundle(forged)


def test_case_bundle_verifier_rejects_rehashed_evidence_planned_round_mismatch(tmp_path):
    """Evidence cannot be reassigned to another planned round by rebuilding unsigned hashes."""
    db_path = tmp_path / "agent_farm.db"
    case, _ = _database_with_round_registry(db_path)
    original = tmp_path / "case.zip"
    forged = tmp_path / "forged-evidence-round-spec.zip"
    export_research_case_bundle(db_path, case.case_id, original)

    _rewrite_bundle_json_member(
        original,
        forged,
        "evidence.json",
        lambda payload: payload["observations"][0].update(
            {"round_spec_id": "different-planned-round"}
        ),
    )

    with pytest.raises(
        ResearchCaseBundleError,
        match="evidence_observation_round_spec_identity_mismatch",
    ):
        verify_research_case_bundle(forged)


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("status", {"claimed": "completed"}, "round_registry_status_invalid"),
        ("started_at", 123, "round_registry_started_at_invalid"),
        ("finished_at", [], "round_registry_finished_at_invalid"),
    ],
)
def test_case_bundle_verifier_rejects_invalid_round_lifecycle_fields(
    tmp_path, field, value, error
):
    """Lifecycle metadata is untrusted input even when archive hashes are rebuilt."""
    db_path = tmp_path / "agent_farm.db"
    case, _ = _database_with_round_registry(db_path)
    original = tmp_path / "case.zip"
    forged = tmp_path / f"forged-round-{field}.zip"
    export_research_case_bundle(db_path, case.case_id, original)

    _rewrite_bundle_json_member(
        original,
        forged,
        "rounds.json",
        lambda payload: payload["rounds"][0].update({field: value}),
    )

    with pytest.raises(ResearchCaseBundleError, match=error):
        verify_research_case_bundle(forged)

def test_case_bundle_verifier_rejects_missing_planned_identity_in_runtime_registry(tmp_path):
    """Rehashing a bundle must not erase the planned hypothesis/run linkage."""
    db_path = tmp_path / "agent_farm.db"
    case, _ = _database_with_round_registry(db_path)
    original = tmp_path / "case.zip"
    tasks_forged = tmp_path / "tasks-without-spec.zip"
    evidence_forged = tmp_path / "evidence-without-spec.zip"
    forged = tmp_path / "round-registry-without-spec.zip"
    export_research_case_bundle(db_path, case.case_id, original)

    _rewrite_bundle_json_member(
        original,
        tasks_forged,
        "tasks.json",
        lambda payload: payload["tasks"][0].update({"round_spec_id": None}),
    )
    _rewrite_bundle_json_member(
        tasks_forged,
        evidence_forged,
        "evidence.json",
        lambda payload: payload["observations"][0].update({"round_spec_id": None}),
    )
    _rewrite_bundle_json_member(
        evidence_forged,
        forged,
        "rounds.json",
        lambda payload: payload["rounds"][0].pop("round_spec_id", None),
    )

    with pytest.raises(
        ResearchCaseBundleError,
        match="round_registry_spec_required",
    ):
        verify_research_case_bundle(forged)
def test_case_bundle_export_rejects_runtime_round_without_planned_identity(tmp_path):
    """The exporter must enforce the same plan-to-run invariant as the offline verifier."""
    db_path = tmp_path / "agent_farm.db"
    case, _ = _database_with_round_registry(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute(
            "UPDATE queue SET round_spec_id = NULL WHERE id = ?",
            ("task-001",),
        )
        db.execute(
            "UPDATE evidence_observations SET round_spec_id = NULL WHERE task_id = ?",
            ("task-001",),
        )
        db.execute(
            "UPDATE research_case_rounds SET round_spec_id = NULL WHERE case_id = ?",
            (case.case_id,),
        )

    with pytest.raises(
        ResearchCaseBundleError,
        match="round_registry_spec_required",
    ):
        export_research_case_bundle(
            db_path, case.case_id, tmp_path / "missing-planned-round.zip"
        )

