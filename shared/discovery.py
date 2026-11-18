"""Structured intake contract between lightweight discovery and deep research."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re
from typing import Any


_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_ALLOWED_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
FINDING_SCHEMA = "aegisforge.discovery_finding.v1"


class DiscoveryFindingError(ValueError):
    """Raised when a discovery finding is incomplete or malformed."""


@dataclass(frozen=True, slots=True)
class DiscoveryFinding:
    chain: str
    contract_address: str
    finding_type: str
    severity: str
    title: str
    description: str
    evidence: dict[str, Any]
    observed_block: int
    source: str
    transaction_hash: str | None = None

    def __post_init__(self) -> None:
        required = {
            "chain": self.chain,
            "finding_type": self.finding_type,
            "title": self.title,
            "description": self.description,
            "source": self.source,
        }
        missing = [key for key, value in required.items()
                   if not isinstance(value, str) or not value.strip()]
        if missing:
            raise DiscoveryFindingError("required_fields_missing:" + ",".join(missing))
        if not isinstance(self.contract_address, str) or not _ADDRESS_RE.fullmatch(self.contract_address):
            raise DiscoveryFindingError("contract_address_invalid")
        if self.severity not in _ALLOWED_SEVERITIES:
            raise DiscoveryFindingError("severity_invalid")
        if not isinstance(self.evidence, dict) or not self.evidence:
            raise DiscoveryFindingError("evidence_required")
        if not isinstance(self.observed_block, int) or isinstance(self.observed_block, bool) or self.observed_block < 0:
            raise DiscoveryFindingError("observed_block_invalid")
        if self.transaction_hash is not None and (
            not isinstance(self.transaction_hash, str)
            or not re.fullmatch(r"0x[a-fA-F0-9]{64}", self.transaction_hash)
        ):
            raise DiscoveryFindingError("transaction_hash_invalid")

    @property
    def fingerprint(self) -> str:
        """Stable identity for the same finding on the same chain and contract."""
        identity = {
            "chain": self.chain.lower(),
            "contract_address": self.contract_address.lower(),
            "finding_type": self.finding_type.lower(),
        }
        canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_payload(self) -> dict[str, Any]:
        return {
            "schema": FINDING_SCHEMA,
            **asdict(self),
            "fingerprint": self.fingerprint,
        }

    def to_task_description(self) -> str:
        """Serialize the complete finding for the downstream analyst task."""
        return json.dumps(
            {
                "task_type": "deep_research_intake",
                "discovery_finding": self.to_payload(),
                "instructions": (
                    "Validate this finding independently. Establish root cause, "
                    "reproducibility, exploitability, impact, and falsification evidence. "
                    "Do not report a vulnerability as confirmed without reproducible evidence."
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        )


def enqueue_discovery_finding(queue, finding: DiscoveryFinding) -> tuple[str, bool]:
    """Idempotently hand a discovery finding to the canonical TaskQueue.

    Returns (task_id, created). Failed prior attempts may be retried; pending,
    running, and completed findings are not duplicated.
    """
    if not isinstance(finding, DiscoveryFinding):
        raise TypeError("finding_must_be_DiscoveryFinding")

    queue.db.execute("BEGIN IMMEDIATE")
    try:
        existing = queue.db.execute(
            """
            SELECT id FROM queue
            WHERE fingerprint = ? AND status IN ('pending', 'running', 'completed')
            ORDER BY created_at DESC LIMIT 1
            """,
            (finding.fingerprint,),
        ).fetchone()
        if existing:
            queue.db.commit()
            return existing[0], False

        task_id = queue.add(
            description=finding.to_task_description(),
            role="analyst",
            contract_address=finding.contract_address,
            fingerprint=finding.fingerprint,
        )
        return task_id, True
    except Exception:
        queue.db.rollback()
        raise
