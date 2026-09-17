import sqlite3

from shared.evidence_ledger import EvidenceLedger


def test_ledger_inserts_atoms_and_provenance():
    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    result = ledger.record("task-1", "researcher", {"target:repo-a", "finding:issue-1"})
    assert result == {"inserted": 2, "confirmed": 0}
    assert ledger.stats() == {"atoms": 2, "confirmations": 2}
    assert db.execute("SELECT COUNT(*) FROM evidence_provenance").fetchone()[0] == 2


def test_same_role_reconfirmation_is_aggregated():
    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    atoms = {"target:repo-a"}
    assert ledger.record("task-1", "researcher", atoms)["inserted"] == 1
    assert ledger.record("task-2", "researcher", atoms) == {"inserted": 0, "confirmed": 0}
    row = db.execute("SELECT confirmation_count, independent_role_count FROM evidence_ledger").fetchone()
    assert row == (2, 1)
    assert db.execute("SELECT COUNT(*) FROM evidence_provenance").fetchone()[0] == 1


def test_independent_roles_increase_confirmation_signal():
    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    atoms = {"finding:issue-1"}
    ledger.record("task-1", "researcher", atoms)
    result = ledger.record("task-2", "security_checker", atoms)
    assert result == {"inserted": 0, "confirmed": 1}
    row = db.execute("SELECT confirmation_count, independent_role_count FROM evidence_ledger").fetchone()
    assert row == (2, 2)


def test_provenance_stays_bounded_by_roles():
    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    for i in range(100):
        ledger.record(f"task-{i}", "researcher", {"finding:issue-1"})
    assert db.execute("SELECT COUNT(*) FROM evidence_provenance").fetchone()[0] == 1
    assert db.execute("SELECT observation_count FROM evidence_provenance").fetchone()[0] == 100
