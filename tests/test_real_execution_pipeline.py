import json

from shared import queue as queue_module
from shared import memory as memory_module
from shared.capability_policy import CapabilityDecision
from shared.queue import TaskQueue
from agents.worker import Worker


def test_real_queue_validator_executor_pipeline(tmp_path, monkeypatch):
    db_path = tmp_path / "pipeline.db"
    monkeypatch.setattr(queue_module, "DB_PATH", db_path)
    monkeypatch.setattr(memory_module, "DB_PATH", db_path)

    execution_root = tmp_path / "execution-root"
    target = execution_root / "workspace" / "obsolete.txt"
    target.parent.mkdir(parents=True)
    target.write_text("staging side effect")
    monkeypatch.setenv("AEGISFORGE_EXECUTION_ROOT", str(execution_root))

    queue = TaskQueue()
    ledger = Worker("validator").evidence_ledger

    claims = {}
    for task_id, role, claim_type in (
        ("e-tests", "developer", "tests_passed"),
        ("e-security", "security_checker", "security_scan_passed"),
        ("e-recovery", "developer", "rollback_or_recovery_ready"),
        ("e-recovery-ready", "developer", "recovery_ready"),
    ):
        recorded = ledger.record_capability_claim(task_id, role, claim_type)
        claims[claim_type] = {
            "status": recorded["status"],
            "source": recorded["source"],
            "evidence_id": recorded["evidence_id"],
        }

    parent_intent = {
        "role": "developer",
        "action": "delete",
        "target": "workspace/obsolete.txt",
        "resource": "staging_filesystem",
        "destination": "staging",
        "data_scope": "source_code",
        "irreversible": True,
        "requires_network": False,
        "requires_shell": False,
        "requires_filesystem": True,
        "financial": False,
        "privileged": False,
        "read_only": False,
        "evidence_required": True,
    }
    parent_result = {
        "error": "capability_evidence_required",
        "error_type": "CapabilityEvidenceRequired",
        "status": "blocked",
        "decision": CapabilityDecision.REQUIRE_EVIDENCE.value,
        "intent": parent_intent,
        "evidence_claims": claims,
    }

    parent_id = queue.add(
        description="test governed delete",
        role="developer",
        capability_intent=parent_intent,
    )
    queue.claim("developer-test-worker", role="developer")
    queue.fail(parent_id, result=parent_result)

    validator_intent = {
        "action": "verify",
        "resource": "authorization_prerequisites",
        "destination": "internal",
        "data_scope": "validation_evidence",
        "read_only": True,
        "evidence_required": False,
    }
    validator_id = queue.add(
        description="[CAPABILITY_EVIDENCE_REQUEST] verify authorization prerequisites",
        role="validator",
        parent_task_id=parent_id,
        capability_intent=validator_intent,
        allow_failed_parent=True,
    )

    validator = Worker("validator")
    assert validator.run_once() is True
    validator_result = queue.get_result(validator_id)
    assert validator_result["status"] == "VERIFIED"
    assert validator_result["capability_grant"]["grant"]["task_id"] == parent_id

    execution_rows = queue.db.execute(
        "SELECT id FROM queue WHERE role='executor' AND parent_task_id=?",
        (validator_id,),
    ).fetchall()
    assert len(execution_rows) == 1
    execution_id = execution_rows[0][0]

    executor = Worker("executor")
    assert executor.run_once() is True
    execution_result = queue.get_result(execution_id)

    assert execution_result["execution_mode"] == "capability_grant"
    assert execution_result["status"] == "EXECUTED"
    assert execution_result["original_task_id"] == parent_id
    assert not target.exists()

    receipt = execution_result["receipt"]
    evidence = execution_result["evidence"]
    assert receipt["status"] == "EXECUTED"
    assert evidence["status"] == "EXECUTED"

    # The grant is single-use even though the handoff remains persisted.
    assert queue.get_result(execution_id)["receipt"]["receipt_id"] == receipt["receipt_id"]
