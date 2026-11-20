"""Deterministic, credential-free contract between snapshot collection and fork runtime.

The plan carries only a validated state anchor and fixed internal service
addresses. It is not proof that a Docker topology is running or isolated.
"""
from __future__ import annotations

import hashlib
import json

from agents.security_checker.fork_engine import (
    ForkSnapshotError,
    build_fork_snapshot,
)


PLAN_SCHEMA = "aegisforge.fork_execution_plan.v1"
ANVIL_RPC_URL = "http://anvil:8545"
ADAPTER_RPC_URL = "http://anvil-rpc-adapter:8546"
REQUIRED_NETWORK_PROFILE = "gateway_mediated_internal_v1"
DEFAULT_TIMEOUT_SECONDS = 180
MAX_TIMEOUT_SECONDS = 1800

_PLAN_FIELDS = frozenset(
    {
        "schema",
        "snapshot_sha256",
        "source_chain_id",
        "fork_chain_id",
        "block_number",
        "block_hash",
        "contract_address",
        "runtime_bytecode_sha256",
        "anvil_rpc_url",
        "adapter_rpc_url",
        "required_network_profile",
        "timeout_seconds",
        "external_transactions_enabled",
        "dynamic_verified",
        "confirmed",
    }
)


class ForkExecutionPlanError(ValueError):
    """A fork execution plan is invalid or is not bound to its snapshot."""


def _normalize_snapshot(snapshot: object) -> dict:
    if not isinstance(snapshot, dict) or snapshot.get("schema") != (
        "aegisforge.fork_snapshot.v1"
    ):
        raise ForkExecutionPlanError("snapshot_invalid")
    try:
        normalized = build_fork_snapshot(
            chain_id=snapshot["chain_id"],
            block_number=snapshot["block_number"],
            block_hash=snapshot["block_hash"],
            contract_address=snapshot["contract_address"],
            runtime_bytecode=snapshot["runtime_bytecode"],
        )
    except (KeyError, TypeError, ValueError, ForkSnapshotError) as exc:
        raise ForkExecutionPlanError("snapshot_invalid") from exc
    if normalized != snapshot:
        raise ForkExecutionPlanError("snapshot_invalid")
    return normalized


def _snapshot_digest(snapshot: dict) -> str:
    encoded = json.dumps(
        snapshot,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def build_fork_execution_plan(
    snapshot: dict,
    *,
    fork_chain_id: int,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict:
    """Build a deterministic execution plan from one validated source snapshot.

    Provider URLs, credentials, arbitrary commands, and caller-selected
    service endpoints are intentionally excluded from this contract.
    """
    normalized = _normalize_snapshot(snapshot)
    if (
        isinstance(fork_chain_id, bool)
        or not isinstance(fork_chain_id, int)
        or fork_chain_id <= 0
    ):
        raise ForkExecutionPlanError("fork_chain_id_invalid")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS
    ):
        raise ForkExecutionPlanError("timeout_invalid")

    return {
        "schema": PLAN_SCHEMA,
        "snapshot_sha256": _snapshot_digest(normalized),
        "source_chain_id": normalized["chain_id"],
        "fork_chain_id": fork_chain_id,
        "block_number": normalized["block_number"],
        "block_hash": normalized["block_hash"],
        "contract_address": normalized["contract_address"],
        "runtime_bytecode_sha256": normalized["runtime_bytecode_sha256"],
        "anvil_rpc_url": ANVIL_RPC_URL,
        "adapter_rpc_url": ADAPTER_RPC_URL,
        "required_network_profile": REQUIRED_NETWORK_PROFILE,
        "timeout_seconds": timeout_seconds,
        "external_transactions_enabled": False,
        "dynamic_verified": False,
        "confirmed": False,
    }


def validate_fork_execution_plan(plan: object, snapshot: dict) -> dict:
    """Validate a serialized plan against the exact source snapshot.

    This is an integrity and policy check. It does not attest runtime network
    isolation, RPC provenance, fork execution, or exploitability.
    """
    normalized = _normalize_snapshot(snapshot)
    if not isinstance(plan, dict) or set(plan) != _PLAN_FIELDS:
        raise ForkExecutionPlanError("plan_schema_invalid")

    try:
        expected = build_fork_execution_plan(
            normalized,
            fork_chain_id=plan["fork_chain_id"],
            timeout_seconds=plan["timeout_seconds"],
        )
    except ForkExecutionPlanError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise ForkExecutionPlanError("plan_schema_invalid") from exc

    if plan != expected:
        raise ForkExecutionPlanError("snapshot_binding_mismatch")
    return dict(expected)
