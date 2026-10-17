"""Canonical identity checks for one bounded Research Case execution round.

A round_spec_id identifies a planned hypothesis/technique. A round_id identifies
one concrete execution. They are deliberately separate identity domains.

This pure validation layer performs no database, task, or network operations.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence


class CaseRoundIdentityError(ValueError):
    """A round, task, or evidence record is not canonically bound."""


ROUND_STATUSES = frozenset({"QUEUED", "RUNNING", "COMPLETED", "FAILED", "INCONCLUSIVE"})


def validate_round_record(record: object, *, case_id: str, declared_spec_ids: set[str]) -> dict:
    """Validate a canonical runtime-round record and return a shallow copy."""
    if not isinstance(record, Mapping):
        raise CaseRoundIdentityError("round_record_must_be_object")
    required = {"case_id", "round_id", "round_number", "round_spec_id", "root_task_id", "status", "created_at"}
    optional = {"started_at", "finished_at"}
    if not required.issubset(record):
        raise CaseRoundIdentityError("round_record_required_fields_missing")
    if set(record) - required - optional:
        raise CaseRoundIdentityError("round_record_unexpected_fields")
    if record.get("case_id") != case_id:
        raise CaseRoundIdentityError("round_case_identity_mismatch")
    for field in ("round_id", "root_task_id", "created_at"):
        value = record.get(field)
        if not isinstance(value, str) or not value.strip():
            raise CaseRoundIdentityError(f"round_{field}_invalid")
    number = record.get("round_number")
    if type(number) is not int or number < 1:
        raise CaseRoundIdentityError("round_number_invalid")
    if record.get("status") not in ROUND_STATUSES:
        raise CaseRoundIdentityError("round_status_invalid")
    spec_id = record.get("round_spec_id")
    if spec_id is not None:
        if not isinstance(spec_id, str) or not spec_id.strip():
            raise CaseRoundIdentityError("round_spec_identity_invalid")
        if spec_id not in declared_spec_ids:
            raise CaseRoundIdentityError("round_spec_not_declared_in_case")
    elif declared_spec_ids:
        raise CaseRoundIdentityError("planned_round_missing_spec_binding")
    for field in ("started_at", "finished_at"):
        value = record.get(field)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise CaseRoundIdentityError(f"round_{field}_invalid")
    return dict(record)


def validate_case_round_relationships(*, case_id: str, declared_spec_ids: set[str], rounds: Sequence[object], tasks: Sequence[object], evidence: Sequence[object]) -> None:
    """Fail closed unless tasks and evidence map to one registered runtime round.

    Runtime round IDs are never interpreted as plan/spec identifiers.
    """
    round_by_id: dict[str, dict] = {}
    round_by_root: dict[str, dict] = {}
    round_numbers: set[int] = set()
    for item in rounds:
        record = validate_round_record(item, case_id=case_id, declared_spec_ids=declared_spec_ids)
        round_id, root_id = record["round_id"], record["root_task_id"]
        if round_id in round_by_id:
            raise CaseRoundIdentityError("duplicate_runtime_round_id")
        if root_id in round_by_root:
            raise CaseRoundIdentityError("duplicate_round_root_task_id")
        if record["round_number"] in round_numbers:
            raise CaseRoundIdentityError("duplicate_case_round_number")
        round_by_id[round_id] = record
        round_by_root[root_id] = record
        round_numbers.add(record["round_number"])

    task_by_id: dict[str, dict] = {}
    for task in tasks:
        if not isinstance(task, Mapping):
            raise CaseRoundIdentityError("task_record_must_be_object")
        task_id = task.get("id")
        if not isinstance(task_id, str) or not task_id or task_id in task_by_id:
            raise CaseRoundIdentityError("task_identity_invalid")
        if task.get("research_case_id") != case_id:
            raise CaseRoundIdentityError("task_case_identity_mismatch")
        round_id, spec_id = task.get("round_id"), task.get("round_spec_id")
        if round_id is None:
            if declared_spec_ids:
                raise CaseRoundIdentityError("planned_task_missing_runtime_round")
            if spec_id is not None:
                raise CaseRoundIdentityError("unscoped_task_has_round_spec")
        else:
            if not isinstance(round_id, str) or round_id not in round_by_id:
                raise CaseRoundIdentityError("task_runtime_round_not_registered")
            record = round_by_id[round_id]
            if spec_id != record["round_spec_id"]:
                raise CaseRoundIdentityError("task_round_spec_identity_mismatch")
            if task_id == record["root_task_id"] and task.get("parent_task_id") is not None:
                raise CaseRoundIdentityError("round_root_task_has_parent")
        task_by_id[task_id] = dict(task)

    for record in round_by_id.values():
        root = task_by_id.get(record["root_task_id"])
        if root is None:
            raise CaseRoundIdentityError("round_root_task_missing")
        if root.get("round_id") != record["round_id"]:
            raise CaseRoundIdentityError("round_root_runtime_identity_mismatch")
        if root.get("round_spec_id") != record["round_spec_id"]:
            raise CaseRoundIdentityError("round_root_spec_identity_mismatch")
        if root.get("parent_task_id") is not None:
            raise CaseRoundIdentityError("round_root_task_has_parent")

    for item in evidence:
        if not isinstance(item, Mapping):
            raise CaseRoundIdentityError("evidence_record_must_be_object")
        if item.get("case_id") != case_id:
            raise CaseRoundIdentityError("evidence_case_identity_mismatch")
        task = task_by_id.get(item.get("task_id"))
        if task is None:
            raise CaseRoundIdentityError("evidence_task_not_in_case")
        if item.get("round_id") != task.get("round_id"):
            raise CaseRoundIdentityError("evidence_runtime_round_identity_mismatch")
        if item.get("round_spec_id") != task.get("round_spec_id"):
            raise CaseRoundIdentityError("evidence_round_spec_identity_mismatch")
