import sqlite3

from shared.capability_grant import issue_capability_grant
from shared.capability_policy import ActionIntent, CapabilityPolicy
from shared.evidence_ledger import EvidenceLedger
from shared.task import Task
from agents.worker import Worker


def _delete_intent(target):
    return ActionIntent(
        role="developer",
        action="delete",
        target=target,
        resource="staging_filesystem",
        destination="staging",
        data_scope="source_code",
        irreversible=True,
        requires_filesystem=True,
        read_only=False,
        evidence_required=True,
    )


def test_validator_verified_result_creates_execution_handoff():
    class Queue:
        def __init__(self):
            self.calls = []

        def add(self, **kwargs):
            self.calls.append(kwargs)
            return "execution-task-1"

    worker = Worker.__new__(Worker)
    worker.role = "validator"
    worker.worker_id = "test-validator"
    worker.queue = Queue()
    intent = _delete_intent("workspace/obsolete.txt")
    grant = issue_capability_grant(
        "original-task-1", intent, CapabilityPolicy.VERSION,
        ["recovery-1"], "staging",
    ).to_dict()

    result = worker._enqueue_execution_handoff(
        "validator-task-1",
        {
            "validation_mode": "capability_evidence",
            "status": "VERIFIED",
            "intent": intent.to_dict(),
            "capability_grant": grant,
        },
    )

    assert result == "execution-task-1"
    envelope = worker.queue.calls[0]["capability_intent"]
    assert envelope["action"] == "execute_granted"
    assert envelope["original_task_id"] == "original-task-1"
    assert envelope["capability_grant"]["grant_id"] == grant["grant_id"]
    assert worker.queue.calls[0]["role"] == "executor"


def test_executor_worker_executes_verified_delete(tmp_path, monkeypatch):
    target = tmp_path / "workspace" / "obsolete.txt"
    target.parent.mkdir()
    target.write_text("remove me")

    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    worker = Worker.__new__(Worker)
    worker.role = "executor"
    worker.queue = type("Queue", (), {"db": db})()
    worker.evidence_ledger = ledger
    monkeypatch.setenv("AEGISFORGE_EXECUTION_ROOT", str(tmp_path))

    intent = _delete_intent("workspace/obsolete.txt")
    grant = issue_capability_grant(
        "original-task-1", intent, CapabilityPolicy.VERSION,
        ["recovery-1"], "staging",
    ).to_dict()
    task = Task(
        task_id="execution-task-1",
        description="execute verified delete",
        payload={
            "capability_intent": {
                "action": "execute_granted",
                "original_task_id": "original-task-1",
                "execution_intent": intent.to_dict(),
                "capability_grant": grant,
                "evidence_ids": ["recovery-1"],
            }
        },
    )

    result = worker._execute_granted_task(task)

    assert not target.exists()
    assert result["status"] == "EXECUTED"
    assert result["grant_id"] == grant["grant_id"]
    assert result["evidence"]["status"] == "EXECUTED"


def test_executor_rejects_tampered_origin(tmp_path, monkeypatch):
    db = sqlite3.connect(":memory:")
    worker = Worker.__new__(Worker)
    worker.role = "executor"
    worker.queue = type("Queue", (), {"db": db})()
    worker.evidence_ledger = EvidenceLedger(db)
    monkeypatch.setenv("AEGISFORGE_EXECUTION_ROOT", str(tmp_path))

    intent = _delete_intent("file.txt")
    grant = issue_capability_grant(
        "original-task-1", intent, CapabilityPolicy.VERSION,
        ["recovery-1"], "staging",
    ).to_dict()
    task = Task(
        task_id="execution-task-1",
        description="tampered handoff",
        payload={
            "capability_intent": {
                "action": "execute_granted",
                "original_task_id": "attacker-task",
                "execution_intent": intent.to_dict(),
                "capability_grant": grant,
                "evidence_ids": ["recovery-1"],
            }
        },
    )

    import pytest
    with pytest.raises(ValueError, match="execution_origin_mismatch"):
        worker._execute_granted_task(task)
