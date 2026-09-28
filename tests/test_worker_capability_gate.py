from shared.capability_policy import CapabilityDecision, CapabilityPolicy
from shared.task import Task
from agents.worker import Worker


class FakeQueue:
    def __init__(self, description):
        self.description = description
        self.failed = []
        self.finished = []

    def recover_stale_running(self, stale_minutes=10):
        return []

    def claim(self, worker, role=None):
        return ("task-1", self.description, "pending", None, None, None, None, role, None, None)

    def get_result(self, task_id):
        return None

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


def build_worker(description):
    worker = Worker.__new__(Worker)
    worker.role = "developer"
    worker.worker_id = "test-worker"
    worker.queue = FakeQueue(description)
    worker.memory = FakeMemory()
    worker.policy = CapabilityPolicy()
    worker.agent = FakeAgent()
    return worker


def test_blocked_capability_never_calls_agent():
    worker = build_worker("call unknown external endpoint")

    assert worker.run_once() is False
    assert worker.agent.calls == 0
    assert worker.queue.failed[0][1]["error_type"] == "CapabilityBlocked"
    assert worker.queue.failed[0][1]["decision"] == CapabilityDecision.BLOCK.value


def test_evidence_required_never_calls_agent():
    worker = build_worker("deploy application")

    assert worker.run_once() is False
    assert worker.agent.calls == 0
    assert worker.queue.failed[0][1]["error_type"] == "CapabilityEvidenceRequired"
    assert worker.queue.failed[0][1]["decision"] == CapabilityDecision.REQUIRE_EVIDENCE.value


def test_allowed_capability_calls_agent_and_finishes():
    worker = build_worker("inspect public repository documentation")

    assert worker.run_once() is True
    assert worker.agent.calls == 1
    assert len(worker.queue.finished) == 1
