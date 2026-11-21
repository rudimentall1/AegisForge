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
_SOURCE_PATH_RE = re.compile(r"^[A-Za-z0-9_.@+/-]+$")
_FOUNDRY_ROOT_RE = re.compile(r"^[A-Za-z0-9_.@+/-]+$")
_FOUNDRY_IMAGE_RE = re.compile(
    r"^ghcr\.io/foundry-rs/foundry@sha256:[0-9a-f]{64}$"
)


class CaseValidationError(ValueError):
    """Raised when a research case is incomplete or unsafe to execute."""


def _allowed_techniques() -> frozenset[str]:
    """Lazy import avoids a module cycle with the scope gate."""
    from shared.scope_gate import ALLOWED_TECHNIQUES
    return ALLOWED_TECHNIQUES


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
    disclosure_deadline_days: int | None = None
    target_source_paths: tuple[str, ...] = ()
    foundry_source_root: str = "src"
    test_harness_source: str = ""
    solc_version: str = ""
    foundry_image: str = ""
    positive_control_test: str = ""
    negative_control_test: str = ""

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

        paths = self.target_source_paths
        if isinstance(paths, list):
            paths = tuple(paths)
            object.__setattr__(self, "target_source_paths", paths)
        if not isinstance(paths, tuple):
            raise CaseValidationError("round_target_source_paths_invalid")
        if len(paths) > 500:
            raise CaseValidationError("round_target_source_path_count_exceeded")
        for path in paths:
            if (
                not isinstance(path, str)
                or not path
                or not _SOURCE_PATH_RE.fullmatch(path)
                or len(path) > 1024
                or not path.lower().endswith(".sol")
                or path.startswith("/")
                or "\\" in path
                or any(part in {"", ".", ".."} for part in path.split("/"))
            ):
                raise CaseValidationError("round_target_source_path_invalid")
        if len(set(paths)) != len(paths):
            raise CaseValidationError("round_target_source_path_duplicate")

        source_root = self.foundry_source_root
        if (
            not isinstance(source_root, str)
            or not source_root
            or len(source_root) > 512
            or not _FOUNDRY_ROOT_RE.fullmatch(source_root)
            or source_root.startswith("/")
            or "\\" in source_root
            or any(part in {"", ".", ".."} for part in source_root.split("/"))
        ):
            raise CaseValidationError("round_foundry_source_root_invalid")

        harness = self.test_harness_source
        if not isinstance(harness, str) or "\x00" in harness:
            raise CaseValidationError("round_test_harness_source_invalid")
        if harness and not harness.strip():
            raise CaseValidationError("round_test_harness_source_invalid")
        try:
            harness_bytes = harness.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise CaseValidationError("round_test_harness_source_invalid") from exc
        if len(harness_bytes) > 256 * 1024:
            raise CaseValidationError("round_test_harness_source_too_large")
        if not isinstance(self.solc_version, str):
            raise CaseValidationError("round_solc_version_invalid")
        if self.solc_version and not re.fullmatch(r"\d+\.\d+\.\d+", self.solc_version):
            raise CaseValidationError("round_solc_version_invalid")
        if bool(harness) != bool(self.solc_version):
            raise CaseValidationError("round_foundry_harness_and_solc_version_required_together")
        if not isinstance(self.foundry_image, str):
            raise CaseValidationError("round_foundry_image_invalid")
        if harness and not _FOUNDRY_IMAGE_RE.fullmatch(self.foundry_image):
            raise CaseValidationError("round_foundry_image_digest_required")
        if not harness and self.foundry_image:
            raise CaseValidationError("round_foundry_image_requires_test_harness")
        controls = (self.positive_control_test, self.negative_control_test)
        if any(not isinstance(name, str) for name in controls):
            raise CaseValidationError("round_foundry_control_test_names_invalid")
        if harness:
            if any(not re.fullmatch(r"test[A-Za-z0-9_]+", name) for name in controls):
                raise CaseValidationError("round_foundry_control_test_names_required")
            if controls[0] == controls[1]:
                raise CaseValidationError("round_foundry_control_test_names_must_differ")
        elif any(controls):
            raise CaseValidationError("round_foundry_controls_require_test_harness")

        if not isinstance(self.priority, int) or isinstance(self.priority, bool):
            raise CaseValidationError("round_priority_invalid")
        if self.disclosure_deadline_days is None:
            # Keep the legacy 90-day default for ordinary techniques while
            # applying the shorter default to disclosure-sensitive techniques.
            default_days = 60 if self.technique in {
                "source_pattern", "crypto_primitive_analysis", "differential_revision"
            } else 90
            object.__setattr__(self, "disclosure_deadline_days", default_days)
        if (
            not isinstance(self.disclosure_deadline_days, int)
            or isinstance(self.disclosure_deadline_days, bool)
            or not 7 <= self.disclosure_deadline_days <= 180
        ):
            raise CaseValidationError(
                "round_disclosure_deadline_days_out_of_range:7..180"
            )
        short_deadline_techniques = {
            "crypto_primitive_analysis",
            "differential_revision",
        }
        if (
            self.technique in short_deadline_techniques
            and self.disclosure_deadline_days > 60
        ):
            raise CaseValidationError(
                f"round_disclosure_deadline_days_exceeds_technique_max:"
                f"{self.technique}:60"
            )


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
        allowed = self.allowed_techniques
        if isinstance(allowed, list):
            allowed = tuple(allowed)
            object.__setattr__(self, "allowed_techniques", allowed)
        if not isinstance(allowed, tuple) or not allowed:
            raise CaseValidationError("allowed_techniques_required")
        invalid_techniques = [
            tech for tech in allowed
            if not isinstance(tech, str) or tech not in _allowed_techniques()
        ]
        if invalid_techniques:
            raise CaseValidationError(f"technique_not_allowed:{invalid_techniques[0]}")

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
    try:
        case = ResearchCase(**payload)
        normalized_payload = json.loads(json.dumps(asdict(case), default=str))
        normalized_payload["execution_mode"] = case.execution_mode.value
        normalized_payload["status"] = case.status.value
        # Bindings created before explicit Foundry inputs existed remain verifiable.
        original_rounds = payload.get("rounds", [])
        if isinstance(original_rounds, list):
            for index, original_round in enumerate(original_rounds):
                if isinstance(original_round, dict):
                    for field_name in (
                        "target_source_paths", "foundry_source_root",
                        "test_harness_source", "solc_version", "foundry_image",
                        "positive_control_test", "negative_control_test"
                    ):
                        if field_name not in original_round:
                            normalized_payload["rounds"][index].pop(field_name, None)
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
