import sqlite3

from shared.evidence_ledger import EvidenceLedger


def test_ledger_inserts_atoms_and_provenance():
    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)

    result = ledger.record(
        "task-1",
        "researcher",
        {"target:repo-a", "finding:issue-1"},
    )

    assert result == {"inserted": 2, "confirmed": 0}
    assert ledger.stats() == {"atoms": 2, "confirmations": 2}
    assert db.execute(
        "SELECT COUNT(*) FROM evidence_observations"
    ).fetchone()[0] == 2


def test_duplicate_task_does_not_inflate_confirmations():
    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    atoms = {"target:repo-a"}

    assert ledger.record("task-1", "researcher", atoms)["inserted"] == 1
    assert ledger.record("task-1", "researcher", atoms) == {
        "inserted": 0,
        "confirmed": 0,
    }

    row = db.execute(
        "SELECT confirmation_count, independent_role_count "
        "FROM evidence_ledger"
    ).fetchone()
    assert row == (1, 1)


def test_independent_roles_increase_confirmation_signal():
    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    atoms = {"finding:issue-1"}

    ledger.record("task-1", "researcher", atoms)
    result = ledger.record("task-2", "security_checker", atoms)

    assert result == {"inserted": 0, "confirmed": 1}
    row = db.execute(
        "SELECT confirmation_count, independent_role_count "
        "FROM evidence_ledger"
    ).fetchone()
    assert row == (2, 2)
