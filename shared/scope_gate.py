"""Fail-closed authorization gate for AegisForge research cases.

This module validates the case envelope before any research experiment. It does
not fetch external scope documents or claim that a scope URL's contents are
currently accurate; the supplied scope digest and review date must be checked
by the research owner as part of case preparation.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import re
from urllib.parse import urlparse

from shared.research_case import ExecutionMode, ResearchCase


_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_ALLOWED_MODES = frozenset({
    ExecutionMode.LOCAL,
    ExecutionMode.AUTHORIZED_FORK,
    ExecutionMode.TESTNET,
})


@dataclass(frozen=True, slots=True)
class GateResult:
    """Deterministic scope decision; never a research finding."""

    allowed: bool
    reason: str

    @property
    def status(self) -> str:
        return "ALLOW" if self.allowed else "FAIL"


def validate_case(case: ResearchCase | None) -> GateResult:
    """Return FAIL for incomplete, malformed, or disallowed case envelopes.

    This function deliberately performs no network calls. A missing case,
    malformed immutable identifier, invalid scope reference, invalid review
    date, or unsupported execution mode is denied rather than downgraded to a
    warning. It never returns CONFIRMED or REJECTED.
    """
    if not isinstance(case, ResearchCase):
        return GateResult(False, "research_case_required")

    if not isinstance(case.case_id, str) or not case.case_id.strip():
        return GateResult(False, "case_id_missing")
    if not isinstance(case.target_repository, str) or not case.target_repository.strip():
        return GateResult(False, "target_repository_missing")
    repository = case.target_repository
    if not (
        re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
        or (
            repository.startswith("https://")
            and bool(urlparse(repository).netloc)
        )
    ):
        return GateResult(False, "target_repository_invalid")

    required_case_text = (
        ("hypothesis", "hypothesis_missing"),
        ("attacker_capability", "attacker_capability_missing"),
        ("expected_invariant", "expected_invariant_missing"),
        ("falsification_criteria", "falsification_criteria_missing"),
    )
    for field, reason in required_case_text:
        value = getattr(case, field, None)
        if not isinstance(value, str) or not value.strip():
            return GateResult(False, reason)

    if not isinstance(case.target_commit, str) or not _COMMIT_RE.fullmatch(case.target_commit):
        return GateResult(False, "target_commit_invalid")
    if not isinstance(case.scope_url, str) or not case.scope_url.strip():
        return GateResult(False, "scope_reference_missing")

    parsed = urlparse(case.scope_url)
    if parsed.scheme != "https" or not parsed.netloc:
        return GateResult(False, "scope_reference_invalid")

    if not isinstance(case.scope_digest, str) or not _SHA256_RE.fullmatch(case.scope_digest):
        return GateResult(False, "scope_digest_invalid")

    if not isinstance(case.scope_reviewed_on, str) or not case.scope_reviewed_on.strip():
        return GateResult(False, "scope_review_date_missing")
    try:
        reviewed_on = date.fromisoformat(case.scope_reviewed_on)
    except (TypeError, ValueError):
        return GateResult(False, "scope_review_date_invalid")
    if reviewed_on.isoformat() != case.scope_reviewed_on:
        return GateResult(False, "scope_review_date_invalid")

    if case.execution_mode not in _ALLOWED_MODES:
        return GateResult(False, "execution_mode_not_allowed")

    return GateResult(True, "case_scope_envelope_valid")
