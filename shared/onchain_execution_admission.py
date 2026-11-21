"""Fail-closed admission for explicitly authorized local on-chain reproduction.

Admission resolves only persisted case, target and compiler-verification records.
It does not run Foundry, perform RPC calls, submit transactions or grant public-chain
execution authority. Git-backed TargetExecutionAdmission remains independent.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import Enum
import re
from urllib.parse import urlsplit

from shared.onchain_verification_store import (
    OnchainVerificationRecord,
    OnchainVerificationStore,
)
from shared.onchain_research_case import OnchainResearchCase
from shared.onchain_target_store import OnchainTargetRecord
from shared.queue import TaskQueue


_HASH32_RE = re.compile(r"^[0-9a-f]{64}$")
_BLOCK_HASH_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{64}$")
MAX_SCOPE_REVIEW_AGE_DAYS = 30


class OnchainExecutionAdmissionError(ValueError):
    """A local on-chain reproduction request lacks current persisted authority."""


class OnchainExecutionProfile(str, Enum):
    FOUNDRY_REPRODUCTION = "foundry_reproduction"


@dataclass(frozen=True, slots=True)
class OnchainExecutionRequest:
    """Identity-only request; accepts no source, harness, argv, RPC or transaction."""

    case_id: str
    target_id: str
    block_hash: str
    verification_id: str
    authorization_reference: str
    profile: OnchainExecutionProfile = OnchainExecutionProfile.FOUNDRY_REPRODUCTION

    def __post_init__(self) -> None:
        if not isinstance(self.case_id, str) or not self.case_id.strip():
            raise OnchainExecutionAdmissionError("case_id_required")
        if not isinstance(self.target_id, str) or not _HASH32_RE.fullmatch(self.target_id):
            raise OnchainExecutionAdmissionError("target_id_invalid")
        if not isinstance(self.verification_id, str) or not _HASH32_RE.fullmatch(self.verification_id):
            raise OnchainExecutionAdmissionError("verification_id_invalid")
        if not isinstance(self.block_hash, str) or not _BLOCK_HASH_RE.fullmatch(self.block_hash):
            raise OnchainExecutionAdmissionError("request_block_hash_invalid")
        block_hash = self.block_hash.lower()
        object.__setattr__(
            self,
            "block_hash",
            block_hash if block_hash.startswith("0x") else "0x" + block_hash,
        )
        if not isinstance(self.authorization_reference, str) or not self.authorization_reference.strip():
            raise OnchainExecutionAdmissionError("authorization_reference_required")
        try:
            parsed = urlsplit(self.authorization_reference)
        except ValueError as exc:
            raise OnchainExecutionAdmissionError("authorization_reference_invalid") from exc
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise OnchainExecutionAdmissionError("authorization_reference_invalid")
        try:
            profile = OnchainExecutionProfile(self.profile)
        except (TypeError, ValueError) as exc:
            raise OnchainExecutionAdmissionError("execution_profile_not_allowed") from exc
        object.__setattr__(self, "profile", profile)


@dataclass(frozen=True, slots=True)
class AdmittedOnchainExecution:
    """Persisted, block-pinned context for a later fixed-profile local runner."""

    case: OnchainResearchCase
    target: OnchainTargetRecord
    verification: OnchainVerificationRecord
    profile: OnchainExecutionProfile
    execution_assurance: str = "NOT_RUN"


def admit_onchain_execution(
    queue: TaskQueue,
    verification_store: OnchainVerificationStore,
    request: OnchainExecutionRequest,
) -> AdmittedOnchainExecution:
    """Admit one local reproduction only from current, persisted authorization.

    The latest verification row wins. An older VERIFIED record cannot authorize
    execution after a newer MISMATCH or INCOMPLETE record has been appended.
    """
    if not isinstance(request, OnchainExecutionRequest):
        raise OnchainExecutionAdmissionError("typed_request_required")
    if not isinstance(queue, TaskQueue):
        raise OnchainExecutionAdmissionError("task_queue_required")
    if not isinstance(verification_store, OnchainVerificationStore):
        raise OnchainExecutionAdmissionError("verification_store_required")
    target_store = verification_store.target_store
    db = queue.db
    if target_store.db is not db:
        raise OnchainExecutionAdmissionError("shared_database_connection_required")
    if db.in_transaction:
        raise OnchainExecutionAdmissionError("admission_database_transaction_already_active")

    try:
        db.execute("BEGIN IMMEDIATE")
        case = queue.get_onchain_research_case(request.case_id)
        if case is None:
            raise OnchainExecutionAdmissionError("onchain_research_case_not_registered")
        target = target_store.get(request.target_id)
        if target is None:
            raise OnchainExecutionAdmissionError("onchain_target_not_registered")
        if case.target_id != target.target_id:
            raise OnchainExecutionAdmissionError("case_target_binding_mismatch")
        if request.block_hash != target.block_hash:
            raise OnchainExecutionAdmissionError("request_block_hash_mismatch")
        if request.authorization_reference != case.authorization_reference:
            raise OnchainExecutionAdmissionError("authorization_reference_mismatch")
        if "exploit_reproduction" not in case.allowed_techniques:
            raise OnchainExecutionAdmissionError("exploit_reproduction_not_authorized")

        reviewed_on = date.fromisoformat(case.scope_reviewed_on)
        today = date.today()
        if reviewed_on > today:
            raise OnchainExecutionAdmissionError("scope_review_in_future")
        if (today - reviewed_on).days > MAX_SCOPE_REVIEW_AGE_DAYS:
            raise OnchainExecutionAdmissionError("scope_review_stale")

        verification = verification_store.get(request.verification_id)
        if verification is None:
            raise OnchainExecutionAdmissionError("verification_record_not_found")
        latest = verification_store.latest_for_target(target.target_id)
        if latest is None or latest.verification_id != request.verification_id:
            raise OnchainExecutionAdmissionError("verification_record_not_latest")
        if verification.status != "VERIFIED":
            raise OnchainExecutionAdmissionError(
                f"verification_status_not_verified:{verification.status}"
            )

        expected_binding = (
            target.target_id,
            target.chain_id,
            target.address,
            target.block_number,
            target.block_hash,
            target.source_sha256,
            target.standard_json_input_sha256,
            target.runtime_code_sha256,
        )
        actual_binding = (
            verification.target_id,
            verification.chain_id,
            verification.address,
            verification.block_number,
            verification.block_hash,
            verification.source_sha256,
            verification.standard_json_input_sha256,
            verification.deployed_runtime_sha256,
        )
        if actual_binding != expected_binding:
            raise OnchainExecutionAdmissionError("verification_target_binding_mismatch")
        if not target.runtime_code or not target.standard_json_input:
            raise OnchainExecutionAdmissionError("verified_target_evidence_incomplete")

        db.commit()
        return AdmittedOnchainExecution(
            case=case,
            target=target,
            verification=verification,
            profile=request.profile,
        )
    except Exception:
        if db.in_transaction:
            db.rollback()
        raise
