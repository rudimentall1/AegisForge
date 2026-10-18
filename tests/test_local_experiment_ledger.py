import sqlite3

import pytest

from shared.evidence_ledger import EvidenceLedger
from shared.local_experiment import build_experiment_record


def _fixture():
    db = sqlite3.connect(":memory:")
    db.execute(
        """CREATE TABLE queue (
            id TEXT PRIMARY KEY,
            research_case_id TEXT NOT NULL,
            round_id TEXT NOT NULL,
            status TEXT NOT NULL
        )"""
    )
    db.execute(
        "INSERT INTO queue VALUES (?, ?, ?, ?)",
        ("task-1", "case-1", "runtime-round-1", "completed"),
    )
    db.execute(
        "CREATE TABLE research_cases (case_id TEXT PRIMARY KEY, payload TEXT NOT NULL)"
    )
    db.execute(
        "INSERT INTO research_cases VALUES (?, ?)",
        (
            "case-1",
            '{"case_id":"case-1","target_repository":"example/protocol",'
            '"target_commit":"' + "a" * 40 + '"}',
        ),
    )
    ledger = EvidenceLedger(db)
    record, artifacts = build_experiment_record(
        case_id="case-1",
        round_id="runtime-round-1",
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
            """SELECT case_id, round_id, task_id, record_json,
                      input_bytes, stdout_bytes, stderr_bytes
               FROM local_experiment_records WHERE record_digest = ?""",
            (result["record_digest"],),
        ).fetchone()
        assert result["experiment_status"] == "PASS"
        assert result["stored_artifacts"] == 3
        assert row[:3] == ("case-1", "runtime-round-1", "task-1")
        assert row[4:] == (b"fixed input", b"control passed", b"")
        assert '"target_commit":"' + "a" * 40 + '"' in row[3]
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
