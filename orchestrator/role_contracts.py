"""Typed contracts for the Agent B research-pipeline boundaries.

These contracts intentionally live in orchestrator/ so Agent B can own and
version role handoffs without creating a competing shared evidence schema.
The existing Task and evidence-ledger contracts remain authoritative for their
current responsibilities.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, TypedDict


ROLE_CONTRACT_VERSION = "aegisforge-role-contract-v1"
AGENT_B_ROLES = frozenset({"analyst", "lab_runner", "security_checker"})


class RoleContractError(ValueError):
    """A role input or output does not satisfy its declared interface."""


class ExecutionState(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    INCOMPLETE = "INCOMPLETE"


class ResearchOutcome(str, Enum):
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    NOT_REPRODUCED = "NOT_REPRODUCED"


class AnalystInput(TypedDict, total=False):
    repositories: list[dict[str, Any]]
    opportunities: list[dict[str, Any]]
    research_scope: str


class AnalystOutput(TypedDict):
    agent: str
    task: str
    research_scope: str
    repositories: list[dict[str, Any]]
    analysis: list[dict[str, Any]]
    opportunities: list[dict[str, Any]]
    count: int


class LabRunnerInput(TypedDict, total=False):
    research_case_id: str
    research_case: Any


class LabRunnerOutput(TypedDict):
    research_track: str
    stage: str
    lab_experiments: list[dict[str, Any]]
    lab_summary: dict[str, Any]


class SecurityCheckerInput(TypedDict):
    technical_review: list[dict[str, Any]]


class SecurityCheckerOutput(TypedDict):
    security_reviews: list[dict[str, Any]]
    security_summary: dict[str, Any]
    security_checker_errors: list[dict[str, Any]]
    checked_by: str
    security_analysis_type: str


@dataclass(frozen=True, slots=True)
class RoleError:
    code: str
    message: str
    retryable: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.code, str) or not self.code.strip():
            raise RoleContractError("error code must be a non-empty string")
        if not isinstance(self.message, str) or not self.message.strip():
            raise RoleContractError("error message must be a non-empty string")
        if not isinstance(self.retryable, bool):
            raise RoleContractError("retryable must be a boolean")


@dataclass(frozen=True, slots=True)
class RoleExecutionResult:
    """Separates execution health from a research conclusion.

    A role result is not a finding. In particular, failed, timed-out, or
    incomplete execution can never produce CONFIRMED or REJECTED. Promotion to
    CONFIRMED also requires evidence references and explicit human approval.
    """

    role: str
    execution_state: ExecutionState
    payload: dict[str, Any]
    errors: tuple[RoleError, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    research_outcome: ResearchOutcome | None = None
    human_approved: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.role, str) or self.role not in AGENT_B_ROLES:
            raise RoleContractError(f"unsupported Agent B role: {self.role!r}")
        if isinstance(self.execution_state, str):
            try:
                object.__setattr__(
                    self, "execution_state", ExecutionState(self.execution_state)
                )
            except ValueError as exc:
                raise RoleContractError("unsupported execution state") from exc
        if not isinstance(self.execution_state, ExecutionState):
            raise RoleContractError("unsupported execution state")
        if not isinstance(self.payload, dict):
            raise RoleContractError("role payload must be a dictionary")
        if not isinstance(self.human_approved, bool):
            raise RoleContractError("human_approved must be a boolean")
        if isinstance(self.research_outcome, str):
            try:
                object.__setattr__(
                    self, "research_outcome", ResearchOutcome(self.research_outcome)
                )
            except ValueError as exc:
                raise RoleContractError("unsupported research outcome") from exc
        if self.research_outcome is not None and not isinstance(
            self.research_outcome, ResearchOutcome
        ):
            raise RoleContractError("unsupported research outcome")
        if not isinstance(self.errors, tuple) or any(
            not isinstance(item, RoleError) for item in self.errors
        ):
            raise RoleContractError("errors must be a tuple of RoleError values")
        if not isinstance(self.evidence_refs, tuple) or any(
            not isinstance(item, str) or not item.strip()
            for item in self.evidence_refs
        ):
            raise RoleContractError("evidence_refs must contain non-empty strings")

        if (
            self.execution_state is not ExecutionState.SUCCEEDED
            and self.research_outcome in {
                ResearchOutcome.CONFIRMED,
                ResearchOutcome.REJECTED,
            }
        ):
            raise RoleContractError(
                "failed, timed-out, or incomplete execution cannot yield "
                "CONFIRMED or REJECTED"
            )
        if self.research_outcome is ResearchOutcome.CONFIRMED:
            if not self.evidence_refs:
                raise RoleContractError("CONFIRMED requires evidence references")
            if not self.human_approved:
                raise RoleContractError("CONFIRMED requires human approval")
        if self.research_outcome is ResearchOutcome.REJECTED and not self.evidence_refs:
            raise RoleContractError("REJECTED requires counter-evidence references")


def _mapping(value: Any, *, role: str, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RoleContractError(f"{role}.{field} must be a dictionary")
    return value


def _list_of_mappings(value: Any, *, role: str, field: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise RoleContractError(f"{role}.{field} must be a list")
    if any(not isinstance(item, dict) for item in value):
        raise RoleContractError(f"{role}.{field} must contain dictionaries only")
    return value


def validate_role_input(
    role: str,
    result: Any,
    task_payload: Any = None,
) -> None:
    """Validate the existing handoff shape before a role consumes it."""
    if role not in AGENT_B_ROLES:
        raise RoleContractError(f"unsupported Agent B role: {role!r}")
    result = _mapping(result, role=role, field="input")

    if role == "analyst":
        for field in ("repositories", "opportunities"):
            if field in result:
                _list_of_mappings(result[field], role=role, field=field)
        if "research_scope" in result and (
            not isinstance(result["research_scope"], str)
            or not result["research_scope"].strip()
        ):
            raise RoleContractError("analyst.research_scope must be a non-empty string")

    elif role == "security_checker":
        raw_reviews = result.get("technical_review", [])
        if raw_reviews is None or raw_reviews == []:
            raise RoleContractError(
                "Security Checker received no technical_review from Developer"
            )
        reviews = _list_of_mappings(
            raw_reviews,
            role=role,
            field="technical_review",
        )

    elif role == "lab_runner":
        payload = _mapping(
            task_payload if task_payload is not None else {},
            role=role,
            field="task_payload",
        )
        case_id = payload.get("research_case_id")
        case = payload.get("research_case")
        if (case_id is None) != (case is None):
            raise RoleContractError(
                "lab_runner requires research_case_id and research_case together"
            )
        if case_id is not None:
            if not isinstance(case_id, str) or not case_id.strip():
                raise RoleContractError(
                    "lab_runner.research_case_id must be a non-empty string"
                )
            if getattr(case, "case_id", None) != case_id:
                raise RoleContractError(
                    "lab_runner research case identifier does not match its case"
                )


def validate_role_output(role: str, result: Any) -> None:
    """Validate the established output shape without upgrading its claims."""
    result = _mapping(result, role=role, field="output")
    for field in ("research_outcome", "conclusion"):
        claim = result.get(field)
        if claim is not None and claim != "":
            if not isinstance(claim, str):
                raise RoleContractError(
                    f"{role}.{field} must not contain an agent-authored conclusion"
                )
            raise RoleContractError(
                f"{role} cannot declare a final research conclusion; "
                "agent output is an untrusted proposal"
            )

    if role == "analyst":
        required = (
            "agent", "task", "research_scope", "repositories",
            "analysis", "opportunities", "count",
        )
        missing = [key for key in required if key not in result]
        if missing:
            raise RoleContractError(f"analyst output missing fields: {', '.join(missing)}")
        for field in ("agent", "task", "research_scope"):
            if not isinstance(result[field], str) or not result[field].strip():
                raise RoleContractError(f"analyst.{field} must be a non-empty string")
        for field in ("repositories", "analysis", "opportunities"):
            _list_of_mappings(result[field], role=role, field=field)
        if type(result["count"]) is not int or result["count"] < 0:
            raise RoleContractError("analyst.count must be a non-negative integer")
        if result["count"] != len(result["analysis"]):
            raise RoleContractError("analyst.count must match analysis length")

    elif role == "lab_runner":
        for field in ("research_track", "stage"):
            if not isinstance(result.get(field), str) or not result[field].strip():
                raise RoleContractError(f"lab_runner.{field} must be a non-empty string")
        experiments = _list_of_mappings(
            result.get("lab_experiments"), role=role, field="lab_experiments"
        )
        if not experiments:
            raise RoleContractError("lab_runner.lab_experiments must not be empty")
        summary = _mapping(result.get("lab_summary"), role=role, field="lab_summary")
        required = (
            "experiments_run", "historical_implementation_reproduced",
            "real_private_keys_used", "live_addresses_examined", "claim_status",
        )
        missing = [key for key in required if key not in summary]
        if missing:
            raise RoleContractError(
                f"lab_runner.lab_summary missing fields: {', '.join(missing)}"
            )
        if summary["claim_status"] != "ILLUSTRATIVE_ONLY":
            raise RoleContractError("synthetic lab output must remain ILLUSTRATIVE_ONLY")
        if summary["real_private_keys_used"] is not False:
            raise RoleContractError("synthetic lab must not use real private keys")
        if summary["historical_implementation_reproduced"] is not False:
            raise RoleContractError(
                "synthetic lab must not claim historical implementation reproduction"
            )
        if type(summary["live_addresses_examined"]) is not int or summary["live_addresses_examined"] < 0:
            raise RoleContractError(
                "lab_runner.live_addresses_examined must be a non-negative integer"
            )
        if summary["live_addresses_examined"] != 0:
            raise RoleContractError("synthetic lab must not examine live addresses")
        if type(summary["experiments_run"]) is not int or summary["experiments_run"] < 1:
            raise RoleContractError("lab_runner.experiments_run must be a positive integer")

    elif role == "security_checker":
        for field in ("checked_by", "security_analysis_type"):
            if not isinstance(result.get(field), str) or not result[field].strip():
                raise RoleContractError(
                    f"security_checker.{field} must be a non-empty string"
                )
        reviews = _list_of_mappings(
            result.get("security_reviews"), role=role, field="security_reviews"
        )
        errors = _list_of_mappings(
            result.get("security_checker_errors"),
            role=role,
            field="security_checker_errors",
        )
        summary = _mapping(
            result.get("security_summary"), role=role, field="security_summary"
        )
        required = (
            "repositories_received", "repositories_checked", "inspection_errors",
            "critical_findings", "high_findings", "medium_findings",
            "low_findings", "total_findings",
        )
        missing = [key for key in required if key not in summary]
        if missing:
            raise RoleContractError(
                f"security_checker.security_summary missing fields: {', '.join(missing)}"
            )
        for field in required:
            if type(summary[field]) is not int or summary[field] < 0:
                raise RoleContractError(
                    f"security_checker.security_summary.{field} must be a non-negative integer"
                )
        if summary["repositories_checked"] != len(reviews):
            raise RoleContractError(
                "security_checker.repositories_checked must match security_reviews length"
            )
        if summary["inspection_errors"] != len(errors):
            raise RoleContractError(
                "security_checker.inspection_errors must match error count"
            )
        severity_total = sum(
            summary[field]
            for field in (
                "critical_findings", "high_findings", "medium_findings", "low_findings"
            )
        )
        if summary["total_findings"] != severity_total:
            raise RoleContractError(
                "security_checker.total_findings must equal severity counters"
            )
    else:
        raise RoleContractError(f"unsupported Agent B role: {role!r}")
