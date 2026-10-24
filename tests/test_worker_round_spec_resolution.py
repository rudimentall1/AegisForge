from types import SimpleNamespace

from agents.worker import Worker
from shared.research_case import RoundSpec


class FakeCursor:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class FakeDB:
    def __init__(self, rows):
        self.rows = rows
        self.queries = []

    def execute(self, query, params):
        self.queries.append((query, params))
        return FakeCursor(self.rows.get(params[0]))


def make_round_spec(round_id="round-1"):
    return RoundSpec(
        round_id=round_id,
        technique="source_pattern",
        hypothesis="A bounded source-pattern hypothesis",
        expected_evidence_atoms=("source-pattern-present",),
        falsification_criteria="The pinned source lacks the pattern",
        priority=1,
        disclosure_deadline_days=30,
    )


def make_worker(rows):
    worker = Worker.__new__(Worker)
    worker.queue = SimpleNamespace(db=FakeDB(rows))
    return worker


def test_resolve_round_spec_from_task_round_identity():
    spec = make_round_spec()
    worker = make_worker({"root": (None, spec.round_id, None)})
    case = SimpleNamespace(rounds=(spec,))

    assert worker._resolve_round_spec("root", case) is spec


def test_resolve_round_spec_from_ancestor_when_legacy_child_has_no_round_id():
    spec = make_round_spec()
    worker = make_worker({
        "child": ("root", None, None),
        "root": (None, spec.round_id, None),
    })
    case = SimpleNamespace(rounds=(spec,))

    assert worker._resolve_round_spec("child", case) is spec


def test_resolve_round_spec_returns_none_for_unknown_round_id():
    spec = make_round_spec()
    worker = make_worker({"root": (None, "round-not-in-case", None)})
    case = SimpleNamespace(rounds=(spec,))

    assert worker._resolve_round_spec("root", case) is None


def test_resolve_round_spec_returns_none_for_missing_task():
    spec = make_round_spec()
    worker = make_worker({})
    case = SimpleNamespace(rounds=(spec,))

    assert worker._resolve_round_spec("missing", case) is None


def test_resolve_round_spec_terminates_on_parent_cycle():
    spec = make_round_spec()
    worker = make_worker({
        "child": ("parent", None, None),
        "parent": ("child", None, None),
    })
    case = SimpleNamespace(rounds=(spec,))

    assert worker._resolve_round_spec("child", case) is None


def test_resolve_round_spec_returns_none_without_case():
    worker = make_worker({})

    assert worker._resolve_round_spec("root", None) is None
    assert worker.queue.db.queries == []


def test_resolve_planned_spec_from_real_queue_schema(tmp_path):
    """The worker query resolves planned identity against TaskQueue's SQLite schema."""
    from datetime import datetime, timezone

    from shared.queue import TaskQueue

    spec = make_round_spec("planned-spec-1")
    queue = TaskQueue(db_path=tmp_path / "worker-round-resolution.sqlite3")
    try:
        now = datetime.now(timezone.utc).isoformat()
        queue.db.execute(
            """
            INSERT INTO queue (
                id, description, status, created_at, role, parent_task_id,
                round_id, round_spec_id
            ) VALUES (?, ?, 'pending', ?, ?, ?, ?, ?)
            """,
            (
                "task-child",
                "regression fixture",
                now,
                "lab_runner",
                None,
                "runtime-round-uuid",
                spec.round_id,
            ),
        )
        queue.db.commit()

        worker = Worker.__new__(Worker)
        worker.queue = queue
        case = SimpleNamespace(rounds=(spec,))

        assert worker._resolve_round_spec("task-child", case) is spec
    finally:
        queue.db.close()

def test_unknown_explicit_planned_spec_fails_closed_instead_of_inheriting():
    """A corrupt child binding must not be masked by a valid ancestor binding."""
    spec = make_round_spec("planned-spec-1")
    worker = make_worker({
        "child": ("root", "runtime-round-1", "unknown-planned-spec"),
        "root": (None, "runtime-round-1", spec.round_id),
    })
    case = SimpleNamespace(rounds=(spec,))

    assert worker._resolve_round_spec("child", case) is None

def test_run_once_passes_registered_case_and_resolved_spec_to_agent(tmp_path, monkeypatch):
    """Exercise the normal worker entrypoint against a real SQLite queue."""
    import hashlib

    from shared.capability_policy import ActionIntent, CapabilityDecision
    from shared.case_rounds import start_case_round
    from shared.queue import TaskQueue
    from shared.research_case import CaseStatus, ExecutionMode, ResearchCase

    spec = make_round_spec("planned-spec-1")
    case = ResearchCase(
        case_id="worker-entrypoint-case",
        target_repository="example/project",
        target_commit="a" * 40,
        scope_url="https://github.com/example/project",
        scope_digest=hashlib.sha256(b"worker-entrypoint-scope").hexdigest(),
        scope_reviewed_on="2026-10-24",
        hypothesis=spec.hypothesis,
        attacker_capability="Synthetic local fixture only",
        expected_invariant="The worker preserves the planned case binding",
        falsification_criteria=spec.falsification_criteria,
        execution_mode=ExecutionMode.LOCAL,
        status=CaseStatus.READY,
        allowed_techniques=("source_pattern",),
        rounds=(spec,),
    )
    queue = TaskQueue(db_path=tmp_path / "worker-run-once.sqlite3")
    try:
        queue.register_research_case(case)
        started = start_case_round(queue, case.case_id, spec.round_id)
        captured = {}

        class FakeAgent:
            def run(self, task):
                captured["task"] = task
                return {
                    "status": "INCONCLUSIVE",
                    "synthetic_fixture": True,
                }

        worker = Worker.__new__(Worker)
        worker.role = "source_researcher"
        worker.worker_id = "source-researcher-integration-test"
        worker.agent_id = "source-researcher-test"
        worker.agent_identity = SimpleNamespace(
            to_dict=lambda: {"agent_id": "source-researcher-test"}
        )
        worker.queue = queue
        worker.memory = SimpleNamespace(save_task=lambda task: None)
        worker.agent = FakeAgent()
        worker._capability_decision = lambda task: (
            ActionIntent(role="source_researcher", action="research"),
            {
                "decision": CapabilityDecision.ALLOW,
                "reason": "test-only allow",
            },
        )
        worker._record_capability_decision = lambda *args: None
        worker._enqueue_execution_handoff = lambda *args: None

        monkeypatch.setattr(
            "agents.worker.EvidenceLedger",
            lambda db: SimpleNamespace(record_observation=lambda *args, **kwargs: None),
        )

        assert worker.run_once() is True
        observed = captured["task"]
        assert observed.task_id == started["root_task_id"]
        assert observed.payload["research_case_id"] == case.case_id
        assert observed.payload["research_case"].target_commit == case.target_commit
        assert observed.payload["round_spec"] is not None
        assert observed.payload["round_spec"].round_id == spec.round_id
        assert observed.payload["technique"] == spec.technique

        stored = queue.get_result(started["root_task_id"])
        assert stored["research_case_binding"]["case_id"] == case.case_id
        assert stored["research_case_binding"]["case"]["target_commit"] == case.target_commit
    finally:
        queue.db.close()
