from agents.developer.agent import Developer
from agents.security_checker.agent import SecurityChecker
from agents.worker import Worker
from shared.task import Task


def test_developer_rejects_partial_inspection():
    developer = Developer()

    task = Task(
        task_id="test-developer-integrity",
        description="integrity test",
        payload={},
        result={
            "agent": "analyst",
            "repositories": [
                {"name": "repo/one"},
                {"name": "repo/two"},
                {"name": "repo/three"},
            ],
        },
        status="running",
    )

    def inspect(repo):
        if repo["name"] == "repo/three":
            raise RuntimeError("SIMULATED_FAILURE")

        return {
            "name": repo["name"],
            "technical_maturity": "HIGH",
            "smart_contract_project": True,
            "has_tests": True,
            "has_ci": True,
            "has_audits": False,
        }

    developer._inspect_repository = inspect

    result = developer.run(task)

    assert result.status == "development_failed"
    assert result.result["error_type"] == "PartialInspectionFailure"

    integrity = result.result["developer_integrity"]

    assert integrity["expected_repositories"] == 3
    assert integrity["inspected_repositories"] == 2
    assert integrity["inspection_errors"] == 1
    assert integrity["complete"] is False


def test_security_checker_rejects_partial_inspection():
    security = SecurityChecker()

    task = Task(
        task_id="test-security-integrity",
        description="integrity test",
        payload={},
        result={
            "agent": "developer",
            "technical_review": [
                {"name": "repo/one"},
                {"name": "repo/two"},
                {"name": "repo/three"},
            ],
        },
        status="running",
    )

    def inspect(review):
        if review["name"] == "repo/three":
            raise RuntimeError("SIMULATED_FAILURE")

        return {
            "name": review["name"],
            "security_posture": {
                "score": 90,
                "posture": "STRONG",
            },
            "finding_summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "total": 0,
            },
            "findings": [],
            "manual_review_required": False,
        }

    security._inspect_repository = inspect

    result = security.run(task)

    assert result.status == "security_check_failed"
    assert result.result["error_type"] == (
        "PartialSecurityInspectionFailure"
    )

    integrity = result.result["security_integrity"]

    assert integrity["expected_repositories"] == 3
    assert integrity["checked_repositories"] == 2
    assert integrity["inspection_errors"] == 1
    assert integrity["complete"] is False


def test_worker_routes_failed_agent_to_queue_fail():
    class FakeQueue:
        def __init__(self):
            self.failed = []
            self.finished = []

        def recover_stale_running(self, stale_minutes=10):
            return []

        def claim(self, worker, role=None):
            return (
                "test-task",
                "simulated failure",
                "running",
                worker,
                None,
                None,
                None,
                role,
                None,
                None,
            )

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
        def run(self, task):
            task.status = "development_failed"
            task.result = {
                "agent": "developer",
                "error_type": "PartialInspectionFailure",
                "error": "Developer integrity gate failed",
                "developer_integrity": {
                    "complete": False,
                },
            }
            return task

    worker = Worker("developer")
    worker.queue = FakeQueue()
    worker.memory = FakeMemory()
    worker.agent = FakeAgent()

    worked = worker.run_once()

    assert worked is False
    assert len(worker.queue.failed) == 1
    assert len(worker.queue.finished) == 0
    assert len(worker.memory.saved) == 1

    task_id, result = worker.queue.failed[0]

    assert task_id == "test-task"
    assert result["error_type"] == "PartialInspectionFailure"
    assert result["developer_integrity"]["complete"] is False
