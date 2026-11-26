"""
SSV Network Vulnerability Research Report Module

Production‑grade representation of vulnerability hypothesis research results
for the SSV Network mainnet‑v2.0.0 codebase at commit bbb26a20a07b8a2446dae799b11799e646a8f404.

This module provides a fully typed, validated, and serialisable data model
with comprehensive error handling, logging, and input validation.
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Final, Literal, Self, Tuple, Union
from uuid import UUID, uuid4

import jsonschema
from pydantic import BaseModel, Field, ValidationError

# --------------------------------------------------------------------------- #
# Logging configuration
# --------------------------------------------------------------------------- #
logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
REPORT_SCHEMA_VERSION: Final[str] = "1.0.0"
PINNED_COMMIT: Final[str] = "bbb26a20a07b8a2446dae799b11799e646a8f404"
REPOSITORY_URL: Final[str] = "https://github.com/ssvlabs/ssv-network"
REF_TAG: Final[str] = "mainnet-v2.0.0"
BOUNTY_PROGRAM_URL: Final[str] = (
    "https://immunefi.com/bug-bounty/ssvnetwork/information/"
)
SCOPE_URL: Final[str] = "https://immunefi.com/bug-bounty/ssvnetwork/scope/"

# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class HypothesisStatus(str, Enum):
    """Enumeration of possible hypothesis validation statuses."""

    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    NOT_REPRODUCED = "NOT_REPRODUCED"


class Workstream(str, Enum):
    """Defined research workstreams for systematic coverage."""

    CLUSTER_INVARIANTS = "cluster_invariants"
    MIGRATION_TRANSITIONS = "migration_transitions"
    AUTHORIZATION_ORACLE = "authorization_oracle"
    ADVERSARIAL_FALSIFICATION = "adversarial_falsification"


class SeverityLevel(str, Enum):
    """Standardised severity levels aligned with Immunefi taxonomy."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    NONE = "none"


# --------------------------------------------------------------------------- #
# Data structures
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class SourceReference:
    """Immutable reference to a specific source location in the codebase."""

    file_path: str
    start_line: int
    end_line: int | None = None
    commit_hash: str = PINNED_COMMIT

    def __post_init__(self) -> None:
        if not self.file_path:
            raise ValueError("file_path cannot be empty")
        if self.start_line < 1:
            raise ValueError("start_line must be >= 1")
        if self.end_line is not None and self.end_line < self.start_line:
            raise ValueError("end_line must be >= start_line")

    @property
    def github_url(self) -> str:
        """Generate GitHub URL for this source reference."""
        line_spec = (
            f"#L{self.start_line}"
            if self.end_line is None
            else f"#L{self.start_line}-L{self.end_line}"
        )
        return f"{REPOSITORY_URL}/blob/{self.commit_hash}/{self.file_path}{line_spec}"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AttackerCapabilities:
    """Structured representation of attacker capabilities and preconditions."""

    required_roles: Tuple[str, ...] = field(default_factory=tuple)
    required_contracts: Tuple[str, ...] = field(default_factory=tuple)
    required_state_conditions: Tuple[str, ...] = field(default_factory=tuple)
    external_dependencies: Tuple[str, ...] = field(default_factory=tuple)
    capital_requirements_eth: float = 0.0
    gas_requirements: int = 0

    def __post_init__(self) -> None:
        if self.capital_requirements_eth < 0:
            raise ValueError("capital_requirements_eth cannot be negative")
        if self.gas_requirements < 0:
            raise ValueError("gas_requirements cannot be negative")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class TestCoverage:
    """Documentation of tests, audits, and public disclosures checked."""

    unit_tests_checked: Tuple[str, ...] = field(default_factory=tuple)
    integration_tests_checked: Tuple[str, ...] = field(default_factory=tuple)
    audit_reports_reviewed: Tuple[str, ...] = field(default_factory=tuple)
    public_disclosures_reviewed: Tuple[str, ...] = field(default_factory=tuple)
    fuzzing_campaigns_reviewed: Tuple[str, ...] = field(default_factory=tuple)
    formal_verification_checked: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ProofOfConcept:
    """Minimal reproducible PoC or falsification experiment specification."""

    description: str
    steps: Tuple[str, ...]
    expected_outcome: str
    actual_outcome: str | None = None
    reproduction_commands: Tuple[str, ...] = field(default_factory=tuple)
    environment_requirements: Tuple[str, ...] = field(default_factory=tuple)
    is_local_only: bool = True
    falsifies_hypothesis: bool = False

    def __post_init__(self) -> None:
        if not self.description.strip():
            raise ValueError("description cannot be empty")
        if not self.steps:
            raise ValueError("at least one step is required")
        if not self.expected_outcome.strip():
            raise ValueError("expected_outcome cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ImpactAssessment:
    """Impact assessment tied to bounty scope without severity inflation."""

    affected_components: Tuple[str, ...]
    potential_loss_eth: float = 0.0
    potential_loss_usd: float = 0.0
    affected_users_estimate: int = 0
    scope_category: str
    severity: SeverityLevel = SeverityLevel.NONE
    bounty_eligibility: bool = False
    justification: str = ""

    def __post_init__(self) -> None:
        if self.potential_loss_eth < 0:
            raise ValueError("potential_loss_eth cannot be negative")
        if self.potential_loss_usd < 0:
            raise ValueError("potential_loss_usd cannot be negative")
        if self.affected_users_estimate < 0:
            raise ValueError("affected_users_estimate cannot be negative")
        if not self.scope_category.strip():
            raise ValueError("scope_category cannot be empty")
        if not self.justification.strip():
            raise ValueError("justification cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


# --------------------------------------------------------------------------- #
# Main model
# --------------------------------------------------------------------------- #
class VulnerabilityHypothesis(BaseModel):
    """Complete vulnerability hypothesis with full validation and serialization."""

    model_config = {
        "frozen": True,
        "validate_assignment": True,
        "extra": "forbid",
        "str_strip_whitespace": True,
    }

    id: UUID = Field(default_factory=uuid4)
    hypothesis_number: int = Field(
        ge=1, description="Sequential hypothesis identifier"
    )
    title: str = Field(
        min_length=1, max_length=200, description="Concise hypothesis title"
    )
    workstream: Workstream
    source_reference: SourceReference | None = None
    preconditions: Tuple[str, ...] = Field(default_factory=tuple)
    attacker_capabilities: AttackerCapabilities = Field(
        default_factory=AttackerCapabilities
    )
    expected_invariant: str = Field(
        min_length=1, description="Expected invariant that should hold"
    )
    observed_behavior: str = Field(
        min_length=1, description="Observed or hypothesized behavior"
    )
    tests_checked: TestCoverage = Field(default_factory=TestCoverage)
    proof_of_concept: ProofOfConcept | None = None
    impact: ImpactAssessment | None = None
    status: HypothesisStatus = HypothesisStatus.INCONCLUSIVE
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # --------------------------------------------------------------------- #
    # Instance helpers
    # --------------------------------------------------------------------- #
    def with_status(self, new_status: HypothesisStatus) -> Self:
        """Return a new instance with updated status."""
        logger.debug("Updating status from %s to %s", self.status, new_status)
        return self.copy(update={"status": new_status, "updated_at": datetime.now(timezone.utc)})

    def with_proof_of_concept(self, poc: ProofOfConcept) -> Self:
        """Return a new instance with attached proof of concept."""
        logger