"""Explicit trust policy for signed synthetic lab-runner receipts.

Trust records must be provisioned out-of-band. This policy checks key lifecycle,
provider binding, and signed execution-time freshness before reserving a receipt
in the durable replay registry. It cannot prove that a runner is honest.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Mapping

from shared.attestation_replay_registry import (
    AttestationReplayRegistryError,
    verify_and_record_attestation,
)
from shared.lab_execution_receipt import LabExecutionReceiptError, verify_signed_receipt


class RunnerTrustPolicyError(ValueError):
    """Raised when a trusted runner key or receipt violates local policy."""


@dataclass(frozen=True)
class RunnerTrustKey:
    """Out-of-band trust record for one runner signing key."""

    provider_id: str
    public_key: bytes
    not_before: str
    not_after: str
    revoked_at: str | None = None


def _parse_utc(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise RunnerTrustPolicyError(f"invalid_timestamp:{field}")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except (TypeError, ValueError) as exc:
        raise RunnerTrustPolicyError(f"invalid_timestamp:{field}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise RunnerTrustPolicyError(f"timestamp_timezone_required:{field}")
    return parsed.astimezone(timezone.utc)


def verify_with_runner_trust_policy(
    dossier: dict,
    envelope: dict,
    *,
    trusted_keys: Mapping[str, RunnerTrustKey],
    database_path: str | Path,
    now: datetime | None = None,
    max_age: timedelta = timedelta(minutes=15),
    future_skew: timedelta = timedelta(seconds=30),
) -> dict:
    """Apply key lifecycle and freshness policy, then atomically record receipt.

    `now` is injectable for deterministic tests; production callers should omit
    it. The caller is responsible for provisioning trusted_keys out-of-band.
    Revocation is immediate: a revoked key is rejected even for older receipts.
    """
    if max_age < timedelta(0) or future_skew < timedelta(0):
        raise RunnerTrustPolicyError("negative_freshness_window")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise RunnerTrustPolicyError("current_time_timezone_required")
    current = current.astimezone(timezone.utc)

    if not isinstance(envelope, dict) or not isinstance(dossier, dict):
        raise RunnerTrustPolicyError("dossier_and_envelope_objects_required")
    key_id = envelope.get("key_id")
    record = trusted_keys.get(key_id) if isinstance(key_id, str) else None
    if record is None:
        raise RunnerTrustPolicyError("runner_key_not_trusted")
    if not isinstance(record.public_key, bytes) or not record.public_key:
        raise RunnerTrustPolicyError("trusted_public_key_must_be_raw_bytes")
    if dossier.get("runner", {}).get("provider_id") != record.provider_id:
        raise RunnerTrustPolicyError("runner_provider_mismatch")

    not_before = _parse_utc(record.not_before, "not_before")
    not_after = _parse_utc(record.not_after, "not_after")
    if not_before >= not_after:
        raise RunnerTrustPolicyError("invalid_key_validity_interval")
    if current < not_before:
        raise RunnerTrustPolicyError("runner_key_not_yet_valid")
    if current >= not_after:
        raise RunnerTrustPolicyError("runner_key_expired")
    if record.revoked_at is not None:
        _parse_utc(record.revoked_at, "revoked_at")
        raise RunnerTrustPolicyError("runner_key_revoked")

    try:
        signed = verify_signed_receipt(envelope, trusted_public_keys={key_id: record.public_key})
    except LabExecutionReceiptError as exc:
        raise RunnerTrustPolicyError(f"attestation_invalid:{exc}") from exc
    completed_at = _parse_utc(envelope["receipt"]["execution"].get("completed_at"), "completed_at")
    if completed_at < not_before or completed_at >= not_after:
        raise RunnerTrustPolicyError("receipt_outside_key_validity_interval")
    if completed_at > current + future_skew:
        raise RunnerTrustPolicyError("receipt_timestamp_in_future")
    if current - completed_at > max_age:
        raise RunnerTrustPolicyError("receipt_stale")

    try:
        result = verify_and_record_attestation(
            dossier, envelope,
            trusted_public_keys={key_id: record.public_key},
            database_path=database_path,
        )
    except AttestationReplayRegistryError as exc:
        raise RunnerTrustPolicyError(str(exc)) from exc
    result = dict(result)
    result["key_lifecycle"] = "VALID_AT_VERIFICATION_TIME"
    result["freshness"] = "WITHIN_LOCAL_POLICY_WINDOW"
    result["runner_independence"] = "NOT_ESTABLISHED"
    result["qualification"] = "NOT_ESTABLISHED"
    return result
