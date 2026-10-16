"""First-class research case contract and fail-closed execution gate.

This module is deliberately independent from the existing queue and agents so it
can be adopted incrementally without duplicating orchestration logic.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import date
from enum import Enum
import hashlib
import json
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
class RoundSpec:
    """One bounded hypothesis/technique round against the case's pinned revision."""

    round_id: str
    technique: str
    hypothesis: str
    expected_evidence_atoms: tuple[str, ...]
    falsification_criteria: str
    priority: int = 0

    def __post_init__(self) -> None:
        for field_name in ("round_id", "technique", "hypothesis", "falsification_criteria"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise CaseValidationError(f"{field_name}_required")
        atoms = self.expected_evidence_atoms
        if isinstance(atoms, list):
            atoms = tuple(atoms)
            object.__setattr__(self, "expected_evidence_atoms", atoms)
        if not isinstance(atoms, tuple) or not atoms:
            raise CaseValidationError("round_expected_evidence_atoms_required")
        if any(not isinstance(atom, str) or not atom.strip() for atom in atoms):
            raise CaseValidationError("round_expected_evidence_atoms_invalid")
        if not isinstance(self.priority, int) or isinstance(self.priority, bool):
            raise CaseValidationError("round_priority_invalid")


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
    allowed_techniques: tuple[str, ...] = ("source_pattern",)
    rounds: tuple[RoundSpec, ...] = ()

    def __post_init__(self) -> None:
        # JSON-loaded case records naturally contain lists/dicts. Normalize them
        # into the immutable tuple/dataclass representation before validation.
        allowed = self.allowed_techniques
        if isinstance(allowed, list):
            allowed = tuple(allowed)
            object.__setattr__(self, "allowed_techniques", allowed)
        if not isinstance(allowed, tuple) or not allowed:
            raise CaseValidationError("allowed_techniques_required")
        if any(not isinstance(tech, str) or not tech.strip() for tech in allowed):
            raise CaseValidationError("technique_not_allowed:invalid")

        rounds = self.rounds
        if isinstance(rounds, list):
            try:
                rounds = tuple(
                    item if isinstance(item, RoundSpec) else RoundSpec(**item)
                    for item in rounds
                )
            except (TypeError, ValueError) as exc:
                raise CaseValidationError("round_spec_invalid") from exc
            object.__setattr__(self, "rounds", rounds)
        if not isinstance(rounds, tuple):
            raise CaseValidationError("rounds_must_be_tuple")
        seen_round_ids = set()
        for round_spec in rounds:
            if not isinstance(round_spec, RoundSpec):
                raise CaseValidationError("round_spec_invalid")
            if round_spec.round_id in seen_round_ids:
                raise CaseValidationError(f"duplicate_round_id:{round_spec.round_id}")
            seen_round_ids.add(round_spec.round_id)
            if round_spec.technique not in allowed:
                raise CaseValidationError(
                    f"round_technique_not_in_allowed:{round_spec.round_id}:{round_spec.technique}"
                )

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


CASE_BINDING_SCHEMA = "aegisforge-research-case-binding-v1"


def research_case_binding(case: ResearchCase) -> dict:
    """Create a canonical, self-checking provenance envelope for a case."""
    if not isinstance(case, ResearchCase):
        raise CaseValidationError("research_case_required")
    payload = json.loads(json.dumps(asdict(case), default=str))
    payload["execution_mode"] = case.execution_mode.value
    payload["status"] = case.status.value
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return {
        "schema_version": CASE_BINDING_SCHEMA,
        "case_id": case.case_id,
        "case_digest": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "case": payload,
    }


def verify_research_case_binding(binding: dict) -> dict:
    """Verify that a result's case identity and immutable case fields agree."""
    if not isinstance(binding, dict) or binding.get("schema_version") != CASE_BINDING_SCHEMA:
        raise CaseValidationError("invalid_research_case_binding_schema")
    payload = binding.get("case")
    if not isinstance(payload, dict):
        raise CaseValidationError("research_case_binding_payload_missing")
    if payload.get("case_id") != binding.get("case_id"):
        raise CaseValidationError("research_case_binding_id_mismatch")
    # A matching digest only proves that the envelope is internally consistent:
    # anyone can recompute it. Validate the payload against the actual case
    # contract before treating it as a usable provenance record.
    try:
        case = ResearchCase(**payload)
        normalized_payload = json.loads(json.dumps(asdict(case), default=str))
        normalized_payload["execution_mode"] = case.execution_mode.value
        normalized_payload["status"] = case.status.value
        if normalized_payload != payload:
            raise CaseValidationError("research_case_binding_payload_invalid")
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    except (CaseValidationError, TypeError, ValueError) as exc:
        if isinstance(exc, CaseValidationError) and str(exc) == "research_case_binding_payload_invalid":
            raise
        raise CaseValidationError("research_case_binding_payload_invalid") from exc
    if digest != binding.get("case_digest"):
        raise CaseValidationError("research_case_binding_digest_mismatch")
    return payload
