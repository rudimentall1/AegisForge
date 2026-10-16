"""First-class research case contract and fail-closed execution gate.

This module is deliberately independent from the existing queue and agents so it
can be adopted incrementally without duplicating orchestration logic.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import Enum
import re
from urllib.parse import urlparse


_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class CaseValidationError(ValueError):
    """Raised when a research case is incomplete or unsafe to execute."""


class ExecutionMode(str, Enum):
    LOCAL = "local"
    AUTHORIZED_FORK = "authorized_fork"
    TESTNET = "testnet"


class CaseStatus(str, Enum):
    DRAFT = "draft"
    READY = "ready"
    RUNNING = "running"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    OUT_OF_SCOPE = "out_of_scope"


@dataclass(frozen=True, slots=True)
class ResearchCase:
    """Immutable identity and authorization envelope for one investigation."""

    case_id: str
    target_repository: str
    target_commit: str
    scope_url: str
    scope_digest: str
    scope_reviewed_on: str
    hypothesis: str
    attacker_capability: str
    expected_invariant: str
    falsification_criteria: str
    execution_mode: ExecutionMode = ExecutionMode.LOCAL
    status: CaseStatus = CaseStatus.READY

    def __post_init__(self) -> None:
        required = {
            "case_id": self.case_id,
            "target_repository": self.target_repository,
            "scope_url": self.scope_url,
            "scope_digest": self.scope_digest,
            "scope_reviewed_on": self.scope_reviewed_on,
            "hypothesis": self.hypothesis,
            "attacker_capability": self.attacker_capability,
            "expected_invariant": self.expected_invariant,
            "falsification_criteria": self.falsification_criteria,
        }
        missing = [name for name, value in required.items()
                   if not isinstance(value, str) or not value.strip()]
        if missing:
            raise CaseValidationError(
                "Missing required research-case fields: " + ", ".join(missing)
            )

        try:
            date.fromisoformat(self.scope_reviewed_on)
        except ValueError as exc:
            raise CaseValidationError("scope_reviewed_on must be an ISO date (YYYY-MM-DD)") from exc

        if not _COMMIT_RE.fullmatch(self.target_commit):
            raise CaseValidationError(
                "target_commit must be a full 40-character Git commit SHA; "
                "branches and movable tags are not accepted"
            )
        if not _SHA256_RE.fullmatch(self.scope_digest):
            raise CaseValidationError("scope_digest must be a SHA-256 hex digest")

        parsed = urlparse(self.scope_url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise CaseValidationError("scope_url must be an absolute HTTPS URL")

        # Accept GitHub owner/repository identifiers or HTTPS repository URLs.
        repo = self.target_repository
        if not (re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo)
                or (repo.startswith("https://") and urlparse(repo).netloc)):
            raise CaseValidationError(
                "target_repository must be owner/repository or an HTTPS URL"
            )

        if isinstance(self.execution_mode, str):
            try:
                object.__setattr__(self, "execution_mode", ExecutionMode(self.execution_mode))
            except ValueError as exc:
                raise CaseValidationError("Unsupported execution mode") from exc
        if isinstance(self.status, str):
            try:
                object.__setattr__(self, "status", CaseStatus(self.status))
            except ValueError as exc:
                raise CaseValidationError("Unsupported case status") from exc

        # This contract intentionally has no live-mainnet mode.
        if self.execution_mode not in {
            ExecutionMode.LOCAL,
            ExecutionMode.AUTHORIZED_FORK,
            ExecutionMode.TESTNET,
        }:
            raise CaseValidationError("Execution mode is not permitted")


def validate_task_binding(case: ResearchCase | None, task_case_id: str | None) -> ResearchCase:
    """Fail closed if a task is not bound to a valid, ready research case."""
    if case is None:
        raise CaseValidationError("Task has no research case; execution denied")
    if not task_case_id or task_case_id != case.case_id:
        raise CaseValidationError("Task/case identifier mismatch; execution denied")
    if case.status not in {CaseStatus.READY, CaseStatus.RUNNING}:
        raise CaseValidationError(
            f"Case status {case.status.value!r} does not permit execution"
        )
    return case


# These roles perform security-research operations whose outputs must be
# traceable to one immutable case. Generic orchestration/business tasks remain
# compatible with legacy queue records.
CASE_REQUIRED_ROLES = frozenset({"source_researcher", "crypto_analyst", "lab_runner"})


def validate_worker_case_binding(
    role: str,
    case: ResearchCase | None,
    task_case_id: str | None,
) -> ResearchCase | None:
    """Enforce case binding at the worker boundary for forensic roles."""
    if not task_case_id:
        if role in CASE_REQUIRED_ROLES:
            raise CaseValidationError(
                f"Role {role!r} requires a registered research case; execution denied"
            )
        if case is not None:
            raise CaseValidationError("Research case payload has no task binding")
        return None
    return validate_task_binding(case, task_case_id)
