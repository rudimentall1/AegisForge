import json
import sqlite3

from shared.capability_policy import CapabilityDecision, CapabilityPolicy
from shared.evidence_ledger import EvidenceLedger
from shared.task import Task
from agents.worker import Worker


class FakeQueue:
    def __init__(self, description, capability_intent=None):
        self.description = description
        self.capability_intent = capability_intent
        self.failed = []
        self.finished = []
        self.added = []

    def recover_stale_running(self, stale_minutes=10):
        return []

    def claim(self, worker, role=None):
        return (
            "task-1",
            self.description,
            "pending",
            None,
            None,
            None,
            None,
            role,
            None,
            None,
            json.dumps(self.capability_intent, sort_keys=True, separators=(",", ":"))
            if self.capability_intent is not None
            else None,
        )

    def get_result(self, task_id):
        return None

    def add(self, description, role=None, parent_task_id=None):
        task_id = f"evidence-{len(self.added) + 1}"
        self.added.append((task_id, description, role, parent_task_id))
        return task_id

    def fail(self, task_id, result=None):
        self.failed.append((task_id, result))

    def finish(self, task_id, result=None):
        self.finished.append((task_id, result))


class FakeMemory:
    def __init__(self):
        self.saved = []

    def save_task(self, task):
        self.saved.append(task)


class FakeAgent:
    def __init__(self):
        self.calls = 0

    def run(self, task):
        self.calls += 1
        task.result = {"ok": True}
        task.status = "done"
        return task


def build_worker(description, capability_intent=None):
    worker = Worker.__new__(Worker)
    worker.role = "developer"
    worker.worker_id = "test-worker"
    worker.queue = FakeQueue(description, capability_intent)
    worker.queue.db = sqlite3.connect(":memory:")
    worker.memory = FakeMemory()
    worker.policy = CapabilityPolicy()
    worker.evidence_ledger = EvidenceLedger(worker.queue.db)
    worker.agent = FakeAgent()
    return worker


def test_blocked_capability_never_calls_agent():
    worker = build_worker(
        "call unknown external endpoint",
        capability_intent={
            "action": "verify",
            "target": "unknown_external_endpoint",
        },
    )

    assert worker.run_once() is False
    assert worker.agent.calls == 0
    assert worker.queue.failed[0][1]["error_type"] == "CapabilityBlocked"
    assert worker.queue.failed[0][1]["decision"] == CapabilityDecision.BLOCK.value


def test_evidence_required_never_calls_agent_and_routes_to_validator():
    worker = build_worker(
        "deployment is discussed in this analysis",
        capability_intent={
            "action": "deploy",
            "destination": "staging",
            "irreversible": True,
            "read_only": False,
        },
    )

    assert worker.run_once() is False
    assert worker.agent.calls == 0
    result = worker.queue.failed[0][1]
    assert result["intent"]["action"] == "deploy"
    assert result["intent"]["destination"] == "staging"
    assert result["intent"]["irreversible"] is True
    assert result["error_type"] == "CapabilityEvidenceRequired"
    assert result["decision"] == CapabilityDecision.REQUIRE_EVIDENCE.value
    assert result["evidence_request"] == {
        "task_id": "evidence-1",
        "role": "validator",
        "status": "pending",
    }
    assert worker.queue.added[0][2:] == ("validator", "task-1")
    assert "deploy" not in worker.queue.added[0][1].lower()


def test_allowed_capability_calls_agent_and_finishes():
    worker = build_worker("inspect public repository documentation")

    assert worker.run_once() is True
    assert worker.agent.calls == 1
    assert len(worker.queue.finished) == 1


def test_capability_decision_is_persisted_as_evidence_observation():
    worker = build_worker(
        "analysis mentions an unknown external endpoint",
        capability_intent={
            "action": "verify",
            "target": "unknown_external_endpoint",
        },
    )

    assert worker.run_once() is False
    row = worker.queue.db.execute(
        "SELECT task_id, role FROM evidence_observations"
    ).fetchone()
    assert row == ("task-1", "developer")
    atom = worker.queue.db.execute(
        "SELECT kind, value FROM evidence_ledger"
    ).fetchone()
    assert atom[0] == "capability_decision"
    assert '"decision":"BLOCK"' in atom[1]
    assert '"reason":"blocked_target"' in atom[1]


def test_structured_intent_controls_worker_decision():
    worker = build_worker(
        "Analyze text containing deploy and transfer words",
        capability_intent={
            "action": "deploy",
            "destination": "staging",
            "irreversible": True,
            "read_only": False,
        },
    )

    assert worker.run_once() is False
    assert worker.agent.calls == 0
    assert worker.queue.failed[0][1]["decision"] == CapabilityDecision.REQUIRE_EVIDENCE.value
