"""Validated dependency graph and bounded scheduling decisions for Agent B.

This module describes execution dependencies and resource budgets only. It does
not execute tasks, interpret research evidence, or produce CONFIRMED/REJECTED
research outcomes. Callers must persist execution results separately and keep
failures/timeouts explicit.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Sequence


_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$")


class TaskGraphError(ValueError):
    """A task graph or scheduler input is malformed or inconsistent."""


class ExecutionStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    INCOMPLETE = "INCOMPLETE"
    BLOCKED = "BLOCKED"


_TERMINAL_FAILURES = {
    ExecutionStatus.FAILED,
    ExecutionStatus.TIMED_OUT,
    ExecutionStatus.INCOMPLETE,
    ExecutionStatus.BLOCKED,
}


@dataclass(frozen=True, slots=True)
class TaskNode:
    node_id: str
    role: str
    dependencies: tuple[str, ...] = ()
    max_attempts: int = 3
    timeout_seconds: int = 300
    resource_units: int = 1

    def __post_init__(self) -> None:
        for field_name, value in (("node_id", self.node_id), ("role", self.role)):
            if not isinstance(value, str) or not value.strip() or not _NAME.fullmatch(value):
                raise TaskGraphError(f"{field_name} must be a valid non-empty identifier")
        if not isinstance(self.dependencies, tuple):
            raise TaskGraphError("dependencies must be a tuple of node IDs")
        if any(
            not isinstance(dep, str) or not dep.strip() or not _NAME.fullmatch(dep)
            for dep in self.dependencies
        ):
            raise TaskGraphError("dependencies must contain valid non-empty node IDs")
        if len(set(self.dependencies)) != len(self.dependencies):
            raise TaskGraphError("dependencies must not contain duplicates")
        if self.node_id in self.dependencies:
            raise TaskGraphError("a task cannot depend on itself")
        if type(self.max_attempts) is not int or self.max_attempts < 1:
            raise TaskGraphError("max_attempts must be a positive integer")
        if type(self.timeout_seconds) is not int or self.timeout_seconds < 1:
            raise TaskGraphError("timeout_seconds must be a positive integer")
        if type(self.resource_units) is not int or self.resource_units < 1:
            raise TaskGraphError("resource_units must be a positive integer")


@dataclass(frozen=True, slots=True)
class SchedulePlan:
    ready: tuple[str, ...]
    blocked: tuple[str, ...]
    waiting: tuple[str, ...]
    running_count: int
    running_resource_units: int


class TaskGraph:
    """A DAG with strict status handling and bounded admission decisions."""

    def __init__(
        self,
        nodes: Sequence[TaskNode],
        *,
        max_parallelism: int = 4,
        max_resource_units: int = 4,
    ) -> None:
        if not isinstance(nodes, (list, tuple)) or not nodes:
            raise TaskGraphError("nodes must be a non-empty list or tuple")
        if type(max_parallelism) is not int or max_parallelism < 1:
            raise TaskGraphError("max_parallelism must be a positive integer")
        if type(max_resource_units) is not int or max_resource_units < 1:
            raise TaskGraphError("max_resource_units must be a positive integer")
        if any(not isinstance(node, TaskNode) for node in nodes):
            raise TaskGraphError("nodes must contain TaskNode values")

        by_id = {node.node_id: node for node in nodes}
        if len(by_id) != len(nodes):
            raise TaskGraphError("node IDs must be unique")
        for node in nodes:
            unknown = sorted(set(node.dependencies) - by_id.keys())
            if unknown:
                raise TaskGraphError(
                    f"task {node.node_id!r} has unknown dependencies: {', '.join(unknown)}"
                )
            if node.resource_units > max_resource_units:
                raise TaskGraphError(
                    f"task {node.node_id!r} exceeds the graph resource budget"
                )

        self._nodes = by_id
        self.max_parallelism = max_parallelism
        self.max_resource_units = max_resource_units
        self._validate_acyclic()

    @property
    def nodes(self) -> Mapping[str, TaskNode]:
        return dict(self._nodes)

    def _validate_acyclic(self) -> None:
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node_id: str) -> None:
            if node_id in visiting:
                raise TaskGraphError("task dependencies contain a cycle")
            if node_id in visited:
                return
            visiting.add(node_id)
            for dependency in self._nodes[node_id].dependencies:
                visit(dependency)
            visiting.remove(node_id)
            visited.add(node_id)

        for node_id in self._nodes:
            visit(node_id)

    @staticmethod
    def _status(value: object, node_id: str) -> ExecutionStatus:
        if isinstance(value, ExecutionStatus):
            return value
        if isinstance(value, str):
            try:
                return ExecutionStatus(value)
            except ValueError as exc:
                raise TaskGraphError(
                    f"task {node_id!r} has unknown execution status {value!r}"
                ) from exc
        raise TaskGraphError(f"task {node_id!r} execution status must be a valid string")

    def plan(self, statuses: Mapping[str, object] | None = None) -> SchedulePlan:
        """Return admissible tasks without executing or upgrading any outcome.

        Missing statuses mean PENDING. Unknown task IDs, malformed status values,
        and inconsistent dependency state fail closed.
        """
        if statuses is None:
            statuses = {}
        if not isinstance(statuses, Mapping):
            raise TaskGraphError("statuses must be a mapping")
        unknown_ids = set(statuses) - self._nodes.keys()
        if unknown_ids:
            raise TaskGraphError(f"statuses contain unknown task IDs: {', '.join(sorted(map(str, unknown_ids)))}")

        normalized = {
            node_id: self._status(statuses.get(node_id, ExecutionStatus.PENDING), node_id)
            for node_id in self._nodes
        }
        running = [
            self._nodes[node_id]
            for node_id, status in normalized.items()
            if status is ExecutionStatus.RUNNING
        ]
        running_count = len(running)
        running_resources = sum(node.resource_units for node in running)
        if running_count > self.max_parallelism:
            raise TaskGraphError("running tasks exceed max_parallelism")
        if running_resources > self.max_resource_units:
            raise TaskGraphError("running tasks exceed max_resource_units")

        ready: list[str] = []
        blocked: list[str] = []
        waiting: list[str] = []
        free_slots = self.max_parallelism - running_count
        free_resources = self.max_resource_units - running_resources

        for node_id, node in self._nodes.items():
            if normalized[node_id] is not ExecutionStatus.PENDING:
                continue
            dependency_states = [normalized[dep] for dep in node.dependencies]
            if any(state in _TERMINAL_FAILURES for state in dependency_states):
                blocked.append(node_id)
                continue
            if not all(state is ExecutionStatus.SUCCEEDED for state in dependency_states):
                waiting.append(node_id)
                continue
            if free_slots > 0 and node.resource_units <= free_resources:
                ready.append(node_id)
                free_slots -= 1
                free_resources -= node.resource_units
            else:
                waiting.append(node_id)

        return SchedulePlan(
            ready=tuple(ready),
            blocked=tuple(blocked),
            waiting=tuple(waiting),
            running_count=running_count,
            running_resource_units=running_resources,
        )

    def retry_allowed(self, node_id: str, *, attempts_used: int, last_status: object) -> bool:
        """Permit bounded retries only after explicit failure/timeout/incomplete."""
        if node_id not in self._nodes:
            raise TaskGraphError(f"unknown task ID {node_id!r}")
        if type(attempts_used) is not int or attempts_used < 1:
            raise TaskGraphError("attempts_used must be a positive integer")
        status = self._status(last_status, node_id)
        if status not in {
            ExecutionStatus.FAILED,
            ExecutionStatus.TIMED_OUT,
            ExecutionStatus.INCOMPLETE,
        }:
            return False
        return attempts_used < self._nodes[node_id].max_attempts
