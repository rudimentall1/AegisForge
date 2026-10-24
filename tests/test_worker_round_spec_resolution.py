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
