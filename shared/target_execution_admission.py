"""Read-only admission gate for future pinned-target tool adapters.

This module resolves execution authority from TaskQueue's persisted records.
Callers cannot submit a ResearchCase payload, target URL, commit, argv, or
environment. It does not spawn processes and is not a sandbox.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from shared.queue import TaskQueue
from shared.research_case import (
    CASE_REQUIRED_ROLES,
    CaseStatus,
    ExecutionMode,
    ResearchCase,
    RoundSpec,
    validate_task_binding,
)


class TargetExecutionAdmissionError(ValueError):
    """A target-tool request is not authorized by persisted case state."""


class AdapterProfile(str, Enum):
    FOUNDRY_TEST = "foundry_test"
    SLITHER_STATIC = "slither_static"


@dataclass(frozen=True, slots=True)
class TargetExecutionRequest:
    """Minimal request: identity only; never accepts target or command material."""

    task_id: str
    adapter_profile: AdapterProfile


@dataclass(frozen=True, slots=True)
class AdmittedTarget:
    """Resolved, immutable execution context sourced from the local registry."""

    task_id: str
    case_id: str
    round_id: str
    round_spec_id: str | None
    adapter_profile: AdapterProfile
    research_case: ResearchCase
    round_spec: RoundSpec | None
    execution_assurance: str = "NOT_RUN"


def admit_target_execution(
    queue: TaskQueue,
    request: TargetExecutionRequest,
) -> AdmittedTarget:
    """Resolve a running lab task against authoritative SQLite state.

    This is an authorization/admission check only. It provides no process
    isolation, source checkout, tool invocation, or execution-truth guarantee.
    """
    if not isinstance(request, TargetExecutionRequest):
        raise TargetExecutionAdmissionError("typed_request_required")
    if not isinstance(request.task_id, str) or not request.task_id.strip():
        raise TargetExecutionAdmissionError("task_id_required")
    try:
        profile = AdapterProfile(request.adapter_profile)
    except (TypeError, ValueError) as exc:
        raise TargetExecutionAdmissionError("adapter_profile_not_allowed") from exc

    db = queue.db
    try:
        db.execute("BEGIN")
        row = db.execute(
            """
            SELECT id, status, role, research_case_id, round_id, round_spec_id
            FROM queue WHERE id = ?
            """,
            (request.task_id,),
        ).fetchone()
        if row is None:
            raise TargetExecutionAdmissionError("task_not_registered")
        task_id, status, role, case_id, round_id, round_spec_id = row

        if role != "lab_runner":
            raise TargetExecutionAdmissionError("task_role_not_lab_runner")
        if status != "running":
            raise TargetExecutionAdmissionError("task_not_running")
        if not case_id:
            raise TargetExecutionAdmissionError("task_case_binding_missing")
        if not round_id:
            raise TargetExecutionAdmissionError("task_runtime_round_binding_missing")

        case = queue.get_research_case(case_id)
        if case is None:
            raise TargetExecutionAdmissionError("research_case_not_registered")
        validate_task_binding(case, case_id)
        if case.status not in {CaseStatus.READY, CaseStatus.RUNNING}:
            raise TargetExecutionAdmissionError("research_case_not_runnable")
        if case.execution_mode is not ExecutionMode.LOCAL:
            raise TargetExecutionAdmissionError("execution_mode_not_supported_by_local_adapter")

        if round_spec_id is None:
            if case.rounds:
                raise TargetExecutionAdmissionError("planned_round_spec_binding_missing")
            round_spec = None
        else:
            round_spec = next(
                (item for item in case.rounds if item.round_id == round_spec_id),
                None,
            )
            if round_spec is None:
                raise TargetExecutionAdmissionError("round_spec_not_declared_in_registered_case")

        round_row = db.execute(
            """
            SELECT root_task_id, round_spec_id, status
            FROM research_case_rounds
            WHERE case_id = ? AND round_id = ?
            """,
            (case_id, round_id),
        ).fetchone()
        if round_row is None:
            raise TargetExecutionAdmissionError("runtime_round_not_registered")
        root_task_id, registered_spec_id, round_status = round_row
        if round_status != "RUNNING":
            raise TargetExecutionAdmissionError("runtime_round_not_running")
        if registered_spec_id != round_spec_id:
            raise TargetExecutionAdmissionError("task_round_spec_registry_mismatch")

        root = db.execute(
            """
            SELECT research_case_id, round_id, role
            FROM queue WHERE id = ?
            """,
            (root_task_id,),
        ).fetchone()
        if root is None or root[0] != case_id or root[1] != round_id:
            raise TargetExecutionAdmissionError("runtime_round_root_binding_invalid")
        if root[2] != "source_researcher":
            raise TargetExecutionAdmissionError("runtime_round_root_role_invalid")

        db.commit()
        return AdmittedTarget(
            task_id=task_id,
            case_id=case_id,
            round_id=round_id,
            round_spec_id=round_spec_id,
            adapter_profile=profile,
            research_case=case,
            round_spec=round_spec,
        )
    except Exception:
        db.rollback()
        raise
