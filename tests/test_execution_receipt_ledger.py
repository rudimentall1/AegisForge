import sqlite3

from shared.evidence_ledger import EvidenceLedger
from shared.execution_gate import ExecutionReceipt


def test_execution_receipt_is_persisted_as_evidence():
    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    receipt = ExecutionReceipt(
        receipt_id="receipt_test",
        task_id="task-1",
        grant_id="grant-1",
        nonce="nonce-1",
        intent_hash="intent-hash",
        policy_version="capability-policy-v1",
        executor_id="test-executor",
        executor_version="1",
        action="deploy",
        target="staging",
        authorized_scope="staging",
        status="EXECUTED",
        executed_at="2026-10-01T00:00:00+00:00",
        result={"ok": True},
    )

    result = ledger.record_execution_receipt("task-1", "developer", receipt)

    assert result["receipt_id"] == "receipt_test"
    assert result["status"] == "EXECUTED"
    row = db.execute(
        "SELECT kind, value FROM evidence_ledger WHERE atom_id = ?",
        (result["evidence_id"],),
    ).fetchone()
    assert row is not None
    assert row[0] == "execution_receipt"
    assert '"receipt_id":"receipt_test"' in row[1]
