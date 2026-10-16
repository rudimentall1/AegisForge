import pytest

from orchestrator.task_graph import (
    ExecutionStatus,
    TaskGraph,
    TaskGraphError,
    TaskNode,
)


def graph(**kwargs):
    return TaskGraph(
        [
            TaskNode("source", "researcher", timeout_seconds=20),
            TaskNode("lab", "lab_runner", dependencies=("source",), max_attempts=2),
            TaskNode("review", "security_checker", dependencies=("lab",)),
        ],
        **kwargs,
    )


def test_only_ready_nodes_are_scheduled_and_dependencies_are_ordered():
    plan = graph().plan()
    assert plan.ready == ("source",)
    assert plan.waiting == ("lab", "review")
    assert plan.blocked == ()


def test_dependency_failure_blocks_descendants_without_calling_them_success():
    plan = graph().plan({"source": "TIMED_OUT"})
    assert plan.ready == ()
    assert plan.blocked == ("lab", "review")


def test_incomplete_dependency_does_not_release_downstream_task():
    plan = graph().plan({"source": "INCOMPLETE"})
    assert "lab" in plan.blocked
    assert "lab" not in plan.ready


def test_parallelism_and_resource_budget_are_enforced():
    dag = TaskGraph(
        [
            TaskNode("a", "analyst", resource_units=2),
            TaskNode("b", "analyst", resource_units=2),
            TaskNode("c", "analyst", resource_units=1),
        ],
        max_parallelism=2,
        max_resource_units=3,
    )
    plan = dag.plan({"a": "RUNNING"})
    assert plan.ready == ("b",)
    assert plan.waiting == ("c",)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"node_id": ""},
        {"node_id": " bad"},
        {"role": " "},
        {"max_attempts": 0},
        {"max_attempts": True},
        {"timeout_seconds": -1},
        {"timeout_seconds": True},
        {"resource_units": 0},
        {"resource_units": True},
        {"dependencies": (" ",)},
        {"dependencies": ("bad/id",)},
    ],
)
def test_node_rejects_malformed_but_nonempty_values(kwargs):
    values = {
        "node_id": "node",
        "role": "worker",
        "dependencies": (),
        "max_attempts": 3,
        "timeout_seconds": 300,
        "resource_units": 1,
    }
    values.update(kwargs)
    with pytest.raises(TaskGraphError):
        TaskNode(**values)


def test_duplicate_ids_unknown_dependencies_and_cycles_are_rejected():
    with pytest.raises(TaskGraphError, match="unique"):
        TaskGraph([TaskNode("x", "worker"), TaskNode("x", "worker")])
    with pytest.raises(TaskGraphError, match="unknown dependencies"):
        TaskGraph([TaskNode("x", "worker", dependencies=("missing",))])
    with pytest.raises(TaskGraphError, match="cycle"):
        TaskGraph(
            [
                TaskNode("x", "worker", dependencies=("y",)),
                TaskNode("y", "worker", dependencies=("x",)),
            ]
        )


@pytest.mark.parametrize("bad_status", ["confirmed", "REJECTEDD", " ", 7, True, None])
def test_unknown_or_malformed_status_fails_closed(bad_status):
    with pytest.raises(TaskGraphError):
        graph().plan({"source": bad_status})


def test_unknown_status_node_is_rejected():
    with pytest.raises(TaskGraphError, match="unknown task IDs"):
        graph().plan({"ghost": "PENDING"})


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("FAILED", True),
        ("TIMED_OUT", True),
        ("INCOMPLETE", True),
        ("SUCCEEDED", False),
        ("RUNNING", False),
        ("PENDING", False),
        ("BLOCKED", False),
    ],
)
def test_retries_are_bounded_and_only_for_explicit_non_success(status, expected):
    dag = TaskGraph([TaskNode("x", "worker", max_attempts=2)])
    assert dag.retry_allowed("x", attempts_used=1, last_status=status) is expected
    assert dag.retry_allowed("x", attempts_used=2, last_status=status) is False


def test_retry_counter_rejects_non_integer_and_invalid_values():
    dag = TaskGraph([TaskNode("x", "worker")])
    for attempts in (0, -1, True, 1.5):
        with pytest.raises(TaskGraphError):
            dag.retry_allowed("x", attempts_used=attempts, last_status="FAILED")


def test_running_resource_overcommit_is_rejected():
    dag = TaskGraph(
        [TaskNode("a", "worker", resource_units=2), TaskNode("b", "worker", resource_units=2)],
        max_parallelism=3,
        max_resource_units=3,
    )
    with pytest.raises(TaskGraphError, match="resource"):
        dag.plan({"a": "RUNNING", "b": "RUNNING"})
