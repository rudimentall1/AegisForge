import sqlite3
from types import SimpleNamespace

from shared.capability_grant import issue_capability_grant as _issue_capability_grant
from shared.authority_state import AuthorityState
from shared.capability_signing import CapabilitySigner
from shared.agent_identity_signing import AgentIdentitySigner
from shared.signed_action_intent import ActionIntentSigner
from shared.capability_policy import ActionIntent, CapabilityPolicy
from shared.evidence_ledger import EvidenceLedger
from shared.agent_authority import AgentAuthorityRegistry
from shared.trust_evaluation import TrustDecision
from shared.task import Task
from agents.worker import Worker
from shared.executor_registry import ExecutorRegistryError


def issue_capability_grant(*args, **kwargs):
    state = kwargs.setdefault("authority_state", AuthorityState.STANDARD)
    intent = kwargs.get("intent") if "intent" in kwargs else (args[1] if len(args) > 1 else None)
    if intent is not None and not getattr(intent, "agent_id", ""):
        from dataclasses import replace
        intent = replace(intent, agent_id="test-agent")
        if "intent" in kwargs:
            kwargs["intent"] = intent
        elif len(args) > 1:
            args = list(args)
            args[1] = intent
            args = tuple(args)
    if intent is not None and "signed_action_intent" not in kwargs:
        identity_signer = AgentIdentitySigner.generate("test-agent", "developer")
        kwargs["signed_action_intent"] = ActionIntentSigner(identity_signer).sign(intent)
    kwargs.setdefault("authority_context", SimpleNamespace(
        agent_id="test-agent",
        authority_epoch=2,
        state=state,
        policy_version=kwargs.get("policy_version", args[2] if len(args) > 2 else "policy-v1"),
    ))
    return _issue_capability_grant(*args, **kwargs)


def _delete_intent(target, agent_id="test-agent"):
    return ActionIntent(
        agent_id=agent_id,
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
        parameters={"outcome_contract": {"type": "state_match", "verifier": "filesystem_independent_v1", "expected_state": "ABSENT"}},
    )


def _seed_authority(db):
    authority = AgentAuthorityRegistry(db)
    authority.register("test-agent")
    authority.record_trust("test-agent", TrustDecision("TRUSTED", "test", "proof-worker-executor", "test"))
    return authority


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
    worker.capability_signer = CapabilitySigner.generate()
    intent = _delete_intent("workspace/obsolete.txt")
    grant = worker.capability_signer.sign(issue_capability_grant(
        "original-task-1", intent, CapabilityPolicy.VERSION,
        ["recovery-1"], "staging",
    )).to_dict()

    result = worker._enqueue_execution_handoff(
        "validator-task-1",
        {
            "validation_mode": "capability_evidence",
            "status": "VERIFIED",
            "agent_id": "test-agent",
            "intent": intent.to_dict(),
            "capability_grant": grant,
        },
    )

    assert result == "execution-task-1"
    envelope = worker.queue.calls[0]["capability_intent"]
    assert envelope["action"] == "execute_granted"
    assert envelope["original_task_id"] == "original-task-1"
    assert envelope["capability_grant"]["grant"]["grant_id"] == grant["grant"]["grant_id"]
    assert worker.queue.calls[0]["role"] == "executor"


def test_validator_handoff_rejects_identity_mismatch():
    class Queue:
        def add(self, **kwargs):
            return "execution-task-1"

    worker = Worker.__new__(Worker)
    worker.role = "validator"
    worker.worker_id = "test-validator"
    worker.queue = Queue()
    worker.capability_signer = CapabilitySigner.generate()
    intent = _delete_intent("workspace/obsolete.txt", agent_id="test-agent")
    grant = worker.capability_signer.sign(issue_capability_grant(
        "original-task-1", intent, CapabilityPolicy.VERSION,
        ["recovery-1"], "staging",
    )).to_dict()
    result = {
        "validation_mode": "capability_evidence",
        "status": "VERIFIED",
        "agent_id": "attacker-agent",
        "intent": intent.to_dict(),
        "capability_grant": grant,
    }
    import pytest
    with pytest.raises(ExecutorRegistryError, match="execution_agent_identity_mismatch"):
        worker._enqueue_execution_handoff("validator-task-1", result)


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
    worker.capability_signer = CapabilitySigner.generate()
    _seed_authority(db)
    monkeypatch.setenv("AEGISFORGE_EXECUTION_ROOT", str(tmp_path))

    intent = _delete_intent("workspace/obsolete.txt")
    grant = worker.capability_signer.sign(issue_capability_grant(
        "original-task-1", intent, CapabilityPolicy.VERSION,
        ["recovery-1"], "staging",
    )).to_dict()
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
    assert result["status"] == "PROVEN"
    assert result["grant_id"] == grant["grant"]["grant_id"]
    assert result["evidence"]["status"] == "EXECUTED"
    assert result["outcome"]["status"] == "PROVEN"
    assert result["outcome_evidence"]["status"] == "PROVEN"


def test_executor_rejects_tampered_origin(tmp_path, monkeypatch):
    db = sqlite3.connect(":memory:")
    worker = Worker.__new__(Worker)
    worker.role = "executor"
    worker.queue = type("Queue", (), {"db": db})()
    worker.evidence_ledger = EvidenceLedger(db)
    worker.capability_signer = CapabilitySigner.generate()
    _seed_authority(db)
    monkeypatch.setenv("AEGISFORGE_EXECUTION_ROOT", str(tmp_path))

    intent = _delete_intent("file.txt")
    grant = worker.capability_signer.sign(issue_capability_grant(
        "original-task-1", intent, CapabilityPolicy.VERSION,
        ["recovery-1"], "staging",
    )).to_dict()
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


def _executor_worker(db, signer):
    worker = Worker.__new__(Worker)
    worker.role = "executor"
    worker.queue = type("Queue", (), {"db": db})()
    worker.evidence_ledger = EvidenceLedger(db)
    worker.capability_signer = signer
    _seed_authority(db)
    return worker


def _execution_task(intent, grant, evidence_ids=None, original_task_id="original-task-1"):
    return Task(
        task_id="execution-task-1",
        description="adversarial execution handoff",
        payload={
            "capability_intent": {
                "action": "execute_granted",
                "original_task_id": original_task_id,
                "execution_intent": intent.to_dict(),
                "capability_grant": grant.to_dict(),
                "evidence_ids": list(evidence_ids if evidence_ids is not None else grant.grant.evidence_ids),
            }
        },
    )


def test_executor_rejects_missing_signed_action_intent_before_effect(tmp_path, monkeypatch):
    db = sqlite3.connect(":memory:")
    target = tmp_path / "workspace" / "obsolete.txt"
    target.parent.mkdir()
    target.write_text("must survive")
    monkeypatch.setenv("AEGISFORGE_EXECUTION_ROOT", str(tmp_path))

    intent = _delete_intent("workspace/obsolete.txt")
    signer = CapabilitySigner.generate()
    grant = signer.sign(issue_capability_grant(
        "original-task-1", intent, CapabilityPolicy.VERSION, ["recovery-1"], "staging"
    ))
    from dataclasses import replace
    legacy_grant = signer.sign(replace(grant.grant, signed_action_intent={}))
    worker = _executor_worker(db, signer)

    import pytest
    with pytest.raises(ValueError, match="signed_action_intent_required"):
        worker._execute_granted_task(_execution_task(intent, legacy_grant))
    assert target.exists()


def test_executor_rejects_tampered_signed_action_intent_before_effect(tmp_path, monkeypatch):
    db = sqlite3.connect(":memory:")
    target = tmp_path / "workspace" / "obsolete.txt"
    target.parent.mkdir()
    target.write_text("must survive")
    monkeypatch.setenv("AEGISFORGE_EXECUTION_ROOT", str(tmp_path))

    intent = _delete_intent("workspace/obsolete.txt")
    signer = CapabilitySigner.generate()
    grant = signer.sign(issue_capability_grant(
        "original-task-1", intent, CapabilityPolicy.VERSION, ["recovery-1"], "staging"
    ))
    from dataclasses import replace
    payload = replace(grant.grant, signed_action_intent={**grant.grant.signed_action_intent, "signature": "tampered"})
    tampered_grant = signer.sign(payload)
    worker = _executor_worker(db, signer)

    import pytest
    with pytest.raises(ValueError, match="signed_action_intent_invalid"):
        worker._execute_granted_task(_execution_task(intent, tampered_grant))
    assert target.exists()


def test_executor_rejects_tampered_intent_before_effect(tmp_path, monkeypatch):
    import sqlite3
    db = sqlite3.connect(":memory:")
    target = tmp_path / "workspace" / "obsolete.txt"
    target.parent.mkdir()
    target.write_text("must survive")
    monkeypatch.setenv("AEGISFORGE_EXECUTION_ROOT", str(tmp_path))

    intent = _delete_intent("workspace/obsolete.txt")
    signer = CapabilitySigner.generate()
    grant = signer.sign(issue_capability_grant("original-task-1", intent, CapabilityPolicy.VERSION, ["recovery-1"], "staging"))
    tampered = _delete_intent("workspace/other.txt")
    worker = _executor_worker(db, signer)

    import pytest
    with pytest.raises(ValueError, match="intent_hash_mismatch"):
        worker._execute_granted_task(_execution_task(tampered, grant))
    assert target.exists()


def test_executor_rejects_tampered_evidence_before_effect(tmp_path, monkeypatch):
    import sqlite3
    db = sqlite3.connect(":memory:")
    target = tmp_path / "workspace" / "obsolete.txt"
    target.parent.mkdir()
    target.write_text("must survive")
    monkeypatch.setenv("AEGISFORGE_EXECUTION_ROOT", str(tmp_path))

    intent = _delete_intent("workspace/obsolete.txt")
    signer = CapabilitySigner.generate()
    grant = signer.sign(issue_capability_grant("original-task-1", intent, CapabilityPolicy.VERSION, ["recovery-1"], "staging"))
    worker = _executor_worker(db, signer)

    import pytest
    with pytest.raises(ValueError, match="execution_evidence_mismatch"):
        worker._execute_granted_task(_execution_task(intent, grant, ["attacker-evidence"]))
    assert target.exists()


def test_executor_grant_is_single_use_across_tasks(tmp_path, monkeypatch):
    import sqlite3
    db = sqlite3.connect(":memory:")
    target = tmp_path / "workspace" / "obsolete.txt"
    target.parent.mkdir()
    target.write_text("delete once")
    monkeypatch.setenv("AEGISFORGE_EXECUTION_ROOT", str(tmp_path))

    intent = _delete_intent("workspace/obsolete.txt")
    signer = CapabilitySigner.generate()
    grant = signer.sign(issue_capability_grant("original-task-1", intent, CapabilityPolicy.VERSION, ["recovery-1"], "staging"))
    worker = _executor_worker(db, signer)

    first = worker._execute_granted_task(_execution_task(intent, grant))
    assert first["status"] == "PROVEN"
    assert first["outcome"]["status"] == "PROVEN"
    assert first["outcome_evidence"]["status"] == "PROVEN"
    assert not target.exists()

    import pytest
    second_task = _execution_task(intent, grant)
    second_task.task_id = "execution-task-2"
    with pytest.raises(ValueError, match="grant_replayed"):
        worker._execute_granted_task(second_task)


def test_executor_rejects_tampered_grant_payload(tmp_path, monkeypatch):
    import sqlite3
    db = sqlite3.connect(":memory:")
    target = tmp_path / "workspace" / "obsolete.txt"
    target.parent.mkdir()
    target.write_text("must survive")
    monkeypatch.setenv("AEGISFORGE_EXECUTION_ROOT", str(tmp_path))

    intent = _delete_intent("workspace/obsolete.txt")
    signer = CapabilitySigner.generate()
    grant = signer.sign(issue_capability_grant("original-task-1", intent, CapabilityPolicy.VERSION, ["recovery-1"], "staging"))
    payload = grant.to_dict()
    payload["grant"]["evidence_hash"] = "tampered"
    task = _execution_task(intent, grant)
    task.payload["capability_intent"]["capability_grant"] = payload
    worker = _executor_worker(db, signer)

    import pytest
    with pytest.raises(ValueError, match="evidence_hash_mismatch"):
        worker._execute_granted_task(task)
    assert target.exists()