import sqlite3

import sqlite3

from shared.evidence_ledger import EvidenceLedger


def test_ledger_inserts_atoms_and_provenance():
    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    result = ledger.record("task-1", "researcher", {"target:repo-a", "finding:issue-1"})
    assert result == {"inserted": 2, "confirmed": 0, "contradictions": 0}
    assert ledger.stats() == {"atoms": 2, "confirmations": 2}
    assert db.execute("SELECT COUNT(*) FROM evidence_provenance").fetchone()[0] == 2


def test_same_task_is_idempotent_for_ledger_observation():
    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    atoms = {"target:repo-a"}
    assert ledger.record("task-1", "researcher", atoms)["inserted"] == 1
    assert ledger.record("task-1", "researcher", atoms) == {
        "inserted": 0,
        "confirmed": 0,
        "contradictions": 0,
    }
    assert ledger.stats() == {"atoms": 1, "confirmations": 1}


def test_same_role_reconfirmation_is_aggregated():
    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    atoms = {"target:repo-a"}
    assert ledger.record("task-1", "researcher", atoms)["inserted"] == 1
    assert ledger.record("task-2", "researcher", atoms) == {"inserted": 0, "confirmed": 0, "contradictions": 0}
    row = db.execute("SELECT confirmation_count, independent_role_count FROM evidence_ledger").fetchone()
    assert row == (2, 1)
    assert db.execute("SELECT COUNT(*) FROM evidence_provenance").fetchone()[0] == 1


def test_independent_roles_increase_confirmation_signal():
    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    atoms = {"finding:issue-1"}
    ledger.record("task-1", "researcher", atoms)
    result = ledger.record("task-2", "security_checker", atoms)
    assert result == {"inserted": 0, "confirmed": 1, "contradictions": 0}
    row = db.execute("SELECT confirmation_count, independent_role_count FROM evidence_ledger").fetchone()
    assert row == (2, 2)


def test_provenance_stays_bounded_by_roles():
    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    for i in range(100):
        ledger.record(f"task-{i}", "researcher", {"finding:issue-1"})
    assert db.execute("SELECT COUNT(*) FROM evidence_provenance").fetchone()[0] == 1
    assert db.execute("SELECT observation_count FROM evidence_provenance").fetchone()[0] == 100



def test_contradictory_security_status_is_recorded():
    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    first = {
        "finding:" + __import__("json").dumps({
            "repository": "repo-a", "file": "x.py", "rule": "r1",
            "description": "issue", "status": "POTENTIAL_RISK"
        }, sort_keys=True, separators=(",", ":"))
    }
    second = {
        "finding:" + __import__("json").dumps({
            "repository": "repo-a", "file": "x.py", "rule": "r1",
            "description": "issue", "status": "SAFE"
        }, sort_keys=True, separators=(",", ":"))
    }
    assert (ledger.record("task-1", "security_checker", first) is not None and ledger.last_contradiction_count == 0)
    assert (ledger.record("task-2", "analyst", second) is not None and ledger.last_contradiction_count == 1)
    assert ledger.contradiction_stats() == {"contradictions": 1}


def test_severity_change_is_not_a_contradiction():
    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    a = {"finding:" + __import__("json").dumps({"repository":"repo-a","file":"x.py","rule":"r1","status":"POTENTIAL_RISK","severity":"LOW"}, sort_keys=True, separators=(",", ":"))}
    b = {"finding:" + __import__("json").dumps({"repository":"repo-a","file":"x.py","rule":"r1","status":"POTENTIAL_RISK","severity":"HIGH"}, sort_keys=True, separators=(",", ":"))}
    ledger.record("task-1", "security_checker", a)
    assert (ledger.record("task-2", "security_checker", b) is not None and ledger.last_contradiction_count == 0)


def test_evidence_quality_is_explainable_and_bounded():
    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    atom = "finding:issue-1"
    ledger.record("task-1", "researcher", {atom})
    atom_id = ledger.atom_id(atom)
    assert ledger.evidence_quality(atom_id)["state"] == "UNCONFIRMED"
    assert ledger.evidence_quality(atom_id)["quality_score"] == 25
    ledger.record("task-2", "security_checker", {atom})
    assert ledger.evidence_quality(atom_id)["state"] == "CORROBORATED"
    assert ledger.evidence_quality(atom_id)["quality_score"] == 60
    assert ledger.evidence_quality(atom_id)["independent_role_count"] == 2
    ledger.record("task-3", "developer", {atom})
    assert ledger.evidence_quality(atom_id)["state"] == "MULTI_SOURCE"
    assert ledger.evidence_quality(atom_id)["quality_score"] == 85


def test_evidence_quality_marks_contradicted_atoms():
    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    a = {"finding:" + __import__("json").dumps({"repository":"repo-a","file":"x.py","rule":"r1","description":"issue","status":"POTENTIAL_RISK"}, sort_keys=True, separators=(",", ":"))}
    b = {"finding:" + __import__("json").dumps({"repository":"repo-a","file":"x.py","rule":"r1","description":"issue","status":"SAFE"}, sort_keys=True, separators=(",", ":"))}
    ledger.record("task-1", "security_checker", a)
    ledger.record("task-2", "analyst", b)
    assert ledger.evidence_quality(ledger.atom_id(next(iter(a))))["state"] == "CONTESTED"
    assert ledger.evidence_quality(ledger.atom_id(next(iter(b))))["state"] == "CONTESTED"


def test_oversized_atom_value_is_bounded():
    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    huge = "x" * (ledger.MAX_ATOM_VALUE_BYTES * 3)
    result = ledger.record("task-1", "researcher", {"target:" + huge})
    assert result["inserted"] == 1
    size = db.execute("SELECT MAX(LENGTH(value)) FROM evidence_ledger").fetchone()[0]
    assert size <= ledger.MAX_ATOM_VALUE_BYTES
