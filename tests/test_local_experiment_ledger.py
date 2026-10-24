import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from shared.evidence_ledger import EvidenceLedger
from shared.local_experiment import build_experiment_record, verify_experiment_record
from shared.local_experiment_bundle import (
    export_persisted_local_experiment_bundle,
    verify_local_experiment_bundle,
)


def _fixture(*, planned=False):
    db = sqlite3.connect(":memory:")
    round_spec_id = "source-pattern-v1" if planned else None
    db.execute(
        """CREATE TABLE queue (
            id TEXT PRIMARY KEY,
            research_case_id TEXT NOT NULL,
            round_id TEXT NOT NULL,
            round_spec_id TEXT,
            status TEXT NOT NULL
        )"""
    )
    db.execute(
        """INSERT INTO queue
           (id, research_case_id, round_id, round_spec_id, status)
           VALUES (?, ?, ?, ?, ?)""",
        ("task-1", "case-1", "runtime-round-1", round_spec_id, "completed"),
    )
    db.execute(
        "CREATE TABLE research_cases (case_id TEXT PRIMARY KEY, payload TEXT NOT NULL)"
    )
    case_payload = {
        "case_id": "case-1",
        "target_repository": "example/protocol",
        "target_commit": "a" * 40,
        "rounds": [{"round_id": round_spec_id}] if planned else [],
    }
    db.execute(
        "INSERT INTO research_cases VALUES (?, ?)",
        ("case-1", json.dumps(case_payload, sort_keys=True)),
    )
    if planned:
        db.execute(
            """CREATE TABLE research_case_rounds (
                round_id TEXT NOT NULL,
                case_id TEXT NOT NULL,
                round_spec_id TEXT
            )"""
        )
        db.execute(
            "INSERT INTO research_case_rounds VALUES (?, ?, ?)",
            ("runtime-round-1", "case-1", round_spec_id),
        )
    ledger = EvidenceLedger(db)
    record, artifacts = build_experiment_record(
        case_id="case-1",
        round_id="runtime-round-1",
        round_spec_id=round_spec_id,
        task_id="task-1",
        target_repository="example/protocol",
        target_commit="a" * 40,
        argv=["pytest", "-q"],
        toolchain={"python": "3.12.1"},
        input_bytes=b"fixed input",
        stdout_bytes=b"control passed",
        stderr_bytes=b"",
        exit_code=0,
    )
    return db, ledger, record, artifacts


def test_local_experiment_persists_raw_artifacts_and_task_binding():
    db, ledger, record, artifacts = _fixture()
    try:
        result = ledger.record_local_experiment(record, artifacts)
        row = db.execute(
            """SELECT case_id, round_id, round_spec_id, task_id, record_json,
                      input_bytes, stdout_bytes, stderr_bytes
               FROM local_experiment_records WHERE record_digest = ?""",
            (result["record_digest"],),
        ).fetchone()
        assert result["experiment_status"] == "PASS"
        assert result["stored_artifacts"] == 3
        assert row[:4] == ("case-1", "runtime-round-1", None, "task-1")
        assert row[5:] == (b"fixed input", b"control passed", b"")
        assert '"target_commit":"' + "a" * 40 + '"' in row[4]
        assert '"round_spec_id":null' in row[4]
        assert result["round_spec_id"] is None
    finally:
        db.close()




def test_local_experiment_persists_and_verifies_planned_round_identity():
    db, ledger, record, artifacts = _fixture(planned=True)
    try:
        stored = ledger.record_local_experiment(record, artifacts)
        row = db.execute(
            "SELECT round_spec_id, record_json FROM local_experiment_records WHERE record_digest = ?",
            (stored["record_digest"],),
        ).fetchone()
        assert row[0] == "source-pattern-v1"
        assert json.loads(row[1])["round_spec_id"] == "source-pattern-v1"

        report = verify_local_experiment_bundle(
            export_persisted_local_experiment_bundle(ledger, stored["record_digest"])
        )
        assert report["status"] == "PASS"
        assert report["round_id"] == "runtime-round-1"
        assert report["round_spec_id"] == "source-pattern-v1"
        assert report["vulnerability_confirmed"] is False
    finally:
        db.close()


def test_local_experiment_rejects_missing_planned_round_identity():
    db, ledger, record, artifacts = _fixture(planned=True)
    try:
        record_without_spec = dict(record)
        record_without_spec["round_spec_id"] = None
        assert verify_experiment_record(record_without_spec, artifacts)["status"] == "PASS"
        with pytest.raises(ValueError, match="local_experiment_round_spec_required"):
            ledger.record_local_experiment(record_without_spec, artifacts)
        assert db.execute("SELECT COUNT(*) FROM local_experiment_records").fetchone()[0] == 0
    finally:
        db.close()


def test_local_experiment_rejects_undeclared_planned_round_identity():
    db, ledger, record, artifacts = _fixture(planned=True)
    try:
        forged = dict(record)
        forged["round_spec_id"] = "another-planned-round"
        assert verify_experiment_record(forged, artifacts)["status"] == "PASS"
        with pytest.raises(ValueError, match="local_experiment_round_spec_not_declared_in_case"):
            ledger.record_local_experiment(forged, artifacts)
        assert db.execute("SELECT COUNT(*) FROM local_experiment_records").fetchone()[0] == 0
    finally:
        db.close()


def test_local_experiment_rejects_task_registry_round_spec_substitution():
    db, ledger, record, artifacts = _fixture(planned=True)
    try:
        db.execute(
            "UPDATE research_case_rounds SET round_spec_id = ? WHERE case_id = ?",
            ("another-planned-round", "case-1"),
        )
        with pytest.raises(
            ValueError, match="local_experiment_round_registry_identity_mismatch"
        ):
            ledger.record_local_experiment(record, artifacts)
        assert db.execute("SELECT COUNT(*) FROM local_experiment_records").fetchone()[0] == 0
    finally:
        db.close()


def test_legacy_v1_local_experiment_record_remains_verifiable():
    db, ledger, record, artifacts = _fixture()
    try:
        legacy = dict(record)
        legacy["schema_version"] = "aegisforge-local-experiment-v1"
        legacy.pop("round_spec_id")
        report = verify_experiment_record(legacy, artifacts)
        assert report["status"] == "PASS"
        assert report["round_spec_id"] is None
    finally:
        db.close()


def test_local_experiment_rejects_task_round_mismatch():
    db, ledger, record, artifacts = _fixture()
    try:
        forged = dict(record)
        forged["round_id"] = "another-round"
        # The verifier checks record/artifact consistency; identity must also
        # be checked against the authoritative queue row.
        from shared.local_experiment import verify_experiment_record

        # Changing round_id does not invalidate artifact hashes, so the
        # queue binding is the layer expected to reject it.
        assert verify_experiment_record(forged, artifacts)["status"] == "PASS"
        with pytest.raises(ValueError, match="local_experiment_task_identity_mismatch"):
            ledger.record_local_experiment(forged, artifacts)
        assert db.execute("SELECT COUNT(*) FROM local_experiment_records").fetchone()[0] == 0
    finally:
        db.close()


def test_local_experiment_rejects_missing_task():
    db, ledger, record, artifacts = _fixture()
    try:
        forged = dict(record)
        forged["task_id"] = "missing-task"
        with pytest.raises(ValueError, match="local_experiment_task_not_found"):
            ledger.record_local_experiment(forged, artifacts)
    finally:
        db.close()



def test_local_experiment_rejects_target_revision_mismatch():
    db, ledger, record, artifacts = _fixture()
    try:
        forged = dict(record)
        forged["target_commit"] = "b" * 40
        with pytest.raises(ValueError, match="local_experiment_target_identity_mismatch"):
            ledger.record_local_experiment(forged, artifacts)
        assert db.execute("SELECT COUNT(*) FROM local_experiment_records").fetchone()[0] == 0
    finally:
        db.close()



def test_local_experiment_storage_has_a_hard_byte_budget():
    db, ledger, record, artifacts = _fixture()
    try:
        ledger.MAX_LOCAL_EXPERIMENT_STORAGE_BYTES = 1
        with pytest.raises(ValueError, match="local_experiment_storage_limit_exceeded"):
            ledger.record_local_experiment(record, artifacts)
        assert db.execute("SELECT COUNT(*) FROM local_experiment_records").fetchone()[0] == 0
    finally:
        db.close()


def test_local_experiment_storage_has_a_record_count_budget():
    db, ledger, record, artifacts = _fixture()
    try:
        ledger.record_local_experiment(record, artifacts)
        ledger.MAX_LOCAL_EXPERIMENT_RECORDS = 1
        changed = dict(record)
        changed["task_id"] = "task-1"
        changed["argv"] = ["pytest", "-q", "--second"]
        with pytest.raises(ValueError, match="local_experiment_record_count_limit_exceeded"):
            ledger.record_local_experiment(changed, artifacts)
    finally:
        db.close()


@pytest.mark.parametrize("task_status", ["pending", "running"])
def test_local_experiment_rejects_nonterminal_task(task_status):
    db, ledger, record, artifacts = _fixture()
    try:
        db.execute("UPDATE queue SET status = ? WHERE id = ?", (task_status, "task-1"))
        db.commit()
        with pytest.raises(ValueError, match="local_experiment_task_not_terminal"):
            ledger.record_local_experiment(record, artifacts)
        assert db.execute("SELECT COUNT(*) FROM local_experiment_records").fetchone()[0] == 0
    finally:
        db.close()



def test_persisted_ledger_record_exports_a_portable_bundle():
    db, ledger, record, artifacts = _fixture()
    try:
        stored = ledger.record_local_experiment(record, artifacts)
        bundle = export_persisted_local_experiment_bundle(
            ledger, stored["record_digest"]
        )
        report = verify_local_experiment_bundle(bundle)
        assert report["status"] == "PASS"
        assert report["case_id"] == "case-1"
        assert report["round_id"] == "runtime-round-1"
        assert report["round_spec_id"] is None
        assert report["task_id"] == "task-1"
        assert report["integrity_only"] is True
        assert report["authenticated_execution"] is False
        assert report["vulnerability_confirmed"] is False
    finally:
        db.close()


def test_persisted_bundle_export_rejects_corrupted_record_json():
    db, ledger, record, artifacts = _fixture()
    try:
        stored = ledger.record_local_experiment(record, artifacts)
        db.execute(
            "UPDATE local_experiment_records SET record_json = ? WHERE record_digest = ?",
            ('{"case_id":"forged"}', stored["record_digest"]),
        )
        db.commit()
        with pytest.raises(
            ValueError, match="local_experiment_persisted_record_digest_mismatch"
        ):
            export_persisted_local_experiment_bundle(ledger, stored["record_digest"])
    finally:
        db.close()


def test_persisted_bundle_export_rejects_artifact_corruption():
    db, ledger, record, artifacts = _fixture()
    try:
        stored = ledger.record_local_experiment(record, artifacts)
        db.execute(
            "UPDATE local_experiment_records SET stdout_bytes = ? WHERE record_digest = ?",
            (b"forged output", stored["record_digest"]),
        )
        db.commit()
        with pytest.raises(ValueError, match="local_experiment_record_invalid"):
            export_persisted_local_experiment_bundle(ledger, stored["record_digest"])
    finally:
        db.close()


def _concurrent_quota_fixture(tmp_path, worker_count):
    database_path = tmp_path / "quota-race.sqlite3"
    connection = sqlite3.connect(database_path, timeout=15)
    connection.execute(
        """CREATE TABLE queue (
            id TEXT PRIMARY KEY,
            research_case_id TEXT NOT NULL,
            round_id TEXT NOT NULL,
            status TEXT NOT NULL
        )"""
    )
    connection.execute(
        "CREATE TABLE research_cases (case_id TEXT PRIMARY KEY, payload TEXT NOT NULL)"
    )
    connection.execute(
        "INSERT INTO research_cases VALUES (?, ?)",
        (
            "case-quota-race",
            json.dumps({
                "case_id": "case-quota-race",
                "target_repository": "example/protocol",
                "target_commit": "a" * 40,
            }),
        ),
    )
    for index in range(worker_count):
        connection.execute(
            "INSERT INTO queue VALUES (?, ?, ?, 'completed')",
            (f"task-{index}", "case-quota-race", "round-quota-race"),
        )
    EvidenceLedger(connection)
    connection.close()

    # Initialize each independent ledger connection before the race starts.
    # This isolates the concurrency under test to validation + quota + insert.
    ledgers = []
    for _ in range(worker_count):
        conn = sqlite3.connect(database_path, timeout=15, check_same_thread=False)
        ledgers.append((conn, EvidenceLedger(conn)))
    return database_path, ledgers


def _race_local_experiment_quota(database_path, ledgers):
    worker_count = len(ledgers)
    barrier = Barrier(worker_count)

    def attempt(index_and_ledger):
        index, (connection, ledger) = index_and_ledger
        record, artifacts = build_experiment_record(
            case_id="case-quota-race",
            round_id="round-quota-race",
            task_id=f"task-{index}",
            target_repository="example/protocol",
            target_commit="a" * 40,
            argv=["synthetic-fixture", str(index)],
            toolchain={"python": "3.12.1"},
            input_bytes=b"input",
            stdout_bytes=b"ok",
            stderr_bytes=b"",
            exit_code=0,
        )
        barrier.wait(timeout=15)
        try:
            ledger.record_local_experiment(record, artifacts)
            return "stored"
        except ValueError as exc:
            return str(exc)
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        outcomes = list(pool.map(attempt, enumerate(ledgers)))
    with sqlite3.connect(database_path) as verify_db:
        stored_count = verify_db.execute(
            "SELECT COUNT(*) FROM local_experiment_records"
        ).fetchone()[0]
    return outcomes, stored_count


def test_concurrent_local_experiment_writes_cannot_exceed_record_count_budget(
    tmp_path, monkeypatch
):
    worker_count = 12
    monkeypatch.setattr(EvidenceLedger, "MAX_LOCAL_EXPERIMENT_RECORDS", 3)
    monkeypatch.setattr(EvidenceLedger, "MAX_LOCAL_EXPERIMENT_STORAGE_BYTES", 1024 * 1024)
    database_path, ledgers = _concurrent_quota_fixture(tmp_path, worker_count)

    outcomes, stored_count = _race_local_experiment_quota(database_path, ledgers)

    assert stored_count == 3
    assert outcomes.count("stored") == 3
    assert outcomes.count("local_experiment_record_count_limit_exceeded") == worker_count - 3


def test_concurrent_local_experiment_writes_cannot_exceed_storage_byte_budget(
    tmp_path, monkeypatch
):
    worker_count = 12
    monkeypatch.setattr(EvidenceLedger, "MAX_LOCAL_EXPERIMENT_RECORDS", 100)
    # Each record stores seven raw artifact bytes (5 input + 2 stdout). Only
    # two records fit; the previous SELECT-then-INSERT flow could race this cap.
    monkeypatch.setattr(EvidenceLedger, "MAX_LOCAL_EXPERIMENT_STORAGE_BYTES", 15)
    database_path, ledgers = _concurrent_quota_fixture(tmp_path, worker_count)

    outcomes, stored_count = _race_local_experiment_quota(database_path, ledgers)

    assert stored_count == 2
    assert outcomes.count("stored") == 2
    assert outcomes.count("local_experiment_storage_limit_exceeded") == worker_count - 2
