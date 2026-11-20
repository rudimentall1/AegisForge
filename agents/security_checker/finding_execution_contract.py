"""Fail-closed request contract for finding-specific EVM fork execution.

The contract binds a reviewed detector finding to one immutable source tree,
one pinned chain snapshot, and one repository-owned bounded Foundry test.
It does not execute tests or confirm vulnerabilities.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Any

from agents.security_checker.fork_engine import ForkSnapshotError, build_fork_snapshot
from agents.security_checker.fork_execution_plan import (
    ForkExecutionPlanError,
    validate_fork_execution_plan,
)


REQUEST_SCHEMA = "aegisforge.finding_execution_request.v1"
_MAX_TIMEOUT_SECONDS = 300
_MAX_STEPS = 100_000
_MAX_PRECONDITIONS = 16
_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})
_FINDING_FIELDS = frozenset({
    "repository", "commit_sha", "source_tree_sha256", "detector_id",
    "severity", "source_file", "line_start", "line_end", "contract_address",
})
_EXPLOIT_FIELDS = frozenset({"path", "sha256"})
_PRECONDITION_FIELDS = frozenset({"kind", "operator", "value"})
_REQUEST_FIELDS = frozenset({
    "schema", "finding_id", "finding", "snapshot_sha256", "chain",
    "exploit_test", "preconditions", "execution", "dynamic_verified",
    "confirmed",
})
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}")
_ADDRESS_RE = re.compile(r"0x[0-9a-f]{40}")
_REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_DETECTOR_RE = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
_SOURCE_PATH_RE = re.compile(r"[A-Za-z0-9_./-]{1,240}")
_EXPLOIT_PATH_RE = re.compile(
    r"tests/fork_exploits/[a-z0-9][a-z0-9_-]{0,63}\.t\.sol"
)
_PRECONDITION_RULES = {
    "caller_role": {"equals": str},
    "balance": {"equals": int, "greater_than": int, "less_than": int},
    "msg_value": {"equals": int, "greater_than": int, "less_than": int},
    "block_timestamp": {"equals": int, "greater_than": int, "less_than": int},
    "block_number": {"equals": int, "greater_than": int, "less_than": int},
}


class FindingExecutionContractError(ValueError):
    """A finding-specific fork execution request is invalid or unbound."""


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _is_int(value: object, *, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def _normalize_finding(finding: object) -> dict:
    if not isinstance(finding, dict) or set(finding) != _FINDING_FIELDS:
        raise FindingExecutionContractError("finding_schema_invalid")

    repository = finding["repository"]
    commit_sha = finding["commit_sha"]
    tree_digest = finding["source_tree_sha256"]
    detector_id = finding["detector_id"]
    severity = finding["severity"]
    source_file = finding["source_file"]
    line_start = finding["line_start"]
    line_end = finding["line_end"]
    address = finding["contract_address"]

    if not isinstance(repository, str) or not _REPOSITORY_RE.fullmatch(repository):
        raise FindingExecutionContractError("finding_repository_invalid")
    if not isinstance(commit_sha, str) or not _COMMIT_RE.fullmatch(commit_sha):
        raise FindingExecutionContractError("finding_commit_invalid")
    if not isinstance(tree_digest, str) or not _SHA256_RE.fullmatch(tree_digest):
        raise FindingExecutionContractError("finding_source_tree_digest_invalid")
    if not isinstance(detector_id, str) or not _DETECTOR_RE.fullmatch(detector_id):
        raise FindingExecutionContractError("finding_detector_invalid")
    if severity not in _SEVERITIES:
        raise FindingExecutionContractError("finding_severity_invalid")
    if (
        not isinstance(source_file, str)
        or not _SOURCE_PATH_RE.fullmatch(source_file)
        or "\\" in source_file
        or PurePosixPath(source_file).is_absolute()
        or any(part in {"", ".", ".."} for part in PurePosixPath(source_file).parts)
    ):
        raise FindingExecutionContractError("finding_source_location_invalid")
    if (
        not _is_int(line_start, minimum=1, maximum=10_000_000)
        or not _is_int(line_end, minimum=line_start, maximum=10_000_000)
        or line_end - line_start > 500
    ):
        raise FindingExecutionContractError("finding_line_range_invalid")
    if not isinstance(address, str) or not _ADDRESS_RE.fullmatch(address):
        raise FindingExecutionContractError("finding_contract_address_invalid")

    return {
        "repository": repository,
        "commit_sha": commit_sha,
        "source_tree_sha256": tree_digest,
        "detector_id": detector_id,
        "severity": severity,
        "source_file": source_file,
        "line_start": line_start,
        "line_end": line_end,
        "contract_address": address,
    }


def _normalize_exploit_test(exploit_test: object) -> dict:
    if not isinstance(exploit_test, dict) or set(exploit_test) != _EXPLOIT_FIELDS:
        raise FindingExecutionContractError("exploit_test_schema_invalid")
    path = exploit_test["path"]
    digest = exploit_test["sha256"]
    if not isinstance(path, str) or not _EXPLOIT_PATH_RE.fullmatch(path):
        raise FindingExecutionContractError("exploit_test_not_allowlisted")
    if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        raise FindingExecutionContractError("exploit_test_digest_invalid")
    return {"path": path, "sha256": digest}


def _normalize_preconditions(preconditions: object) -> list[dict]:
    if (
        not isinstance(preconditions, list)
        or not 1 <= len(preconditions) <= _MAX_PRECONDITIONS
    ):
        raise FindingExecutionContractError("preconditions_invalid")
    normalized = []
    for item in preconditions:
        if not isinstance(item, dict) or set(item) != _PRECONDITION_FIELDS:
            raise FindingExecutionContractError("precondition_schema_invalid")
        kind, operator, value = item["kind"], item["operator"], item["value"]
        allowed = _PRECONDITION_RULES.get(kind)
        if not isinstance(allowed, dict) or operator not in allowed:
            raise FindingExecutionContractError("precondition_kind_or_operator_invalid")
        expected_type = allowed[operator]
        if expected_type is str:
            if not isinstance(value, str) or not value or len(value) > 64:
                raise FindingExecutionContractError("precondition_value_invalid")
        elif not _is_int(value, minimum=0, maximum=2**64 - 1):
            raise FindingExecutionContractError("precondition_value_invalid")
        normalized.append({"kind": kind, "operator": operator, "value": value})
    if len({_canonical_digest(item) for item in normalized}) != len(normalized):
        raise FindingExecutionContractError("preconditions_duplicate")
    return normalized


def _normalize_snapshot(snapshot: object) -> dict:
    if not isinstance(snapshot, dict) or snapshot.get("schema") != "aegisforge.fork_snapshot.v1":
        raise FindingExecutionContractError("snapshot_invalid")
    try:
        normalized = build_fork_snapshot(
            chain_id=snapshot["chain_id"],
            block_number=snapshot["block_number"],
            block_hash=snapshot["block_hash"],
            contract_address=snapshot["contract_address"],
            runtime_bytecode=snapshot["runtime_bytecode"],
        )
    except (KeyError, TypeError, ValueError, ForkSnapshotError) as exc:
        raise FindingExecutionContractError("snapshot_invalid") from exc
    if normalized != snapshot:
        raise FindingExecutionContractError("snapshot_invalid")
    return normalized


def _build_request(
    *, finding: dict, snapshot: dict, plan: dict, exploit_test: dict,
    preconditions: list[dict], timeout_seconds: int, max_steps: int,
) -> dict:
    finding_identity = {
        key: finding[key]
        for key in (
            "repository", "commit_sha", "source_tree_sha256", "detector_id",
            "source_file", "line_start", "line_end", "contract_address",
        )
    }
    finding_id = "sha256:" + _canonical_digest(finding_identity)
    return {
        "schema": REQUEST_SCHEMA,
        "finding_id": finding_id,
        "finding": finding,
        "snapshot_sha256": plan["snapshot_sha256"],
        "chain": {
            "source_chain_id": snapshot["chain_id"],
            "fork_chain_id": plan["fork_chain_id"],
            "block_number": snapshot["block_number"],
            "block_hash": snapshot["block_hash"],
            "contract_address": snapshot["contract_address"],
            "runtime_bytecode_sha256": snapshot["runtime_bytecode_sha256"],
        },
        "exploit_test": exploit_test,
        "preconditions": preconditions,
        "execution": {
            "runtime_profile": plan["required_network_profile"],
            "timeout_seconds": timeout_seconds,
            "max_steps": max_steps,
            "network_access": False,
            "external_transactions_enabled": False,
            "local_fork_transactions_enabled": True,
            "arbitrary_shell_enabled": False,
            "arbitrary_test_path_enabled": False,
        },
        "dynamic_verified": False,
        "confirmed": False,
    }


def build_finding_execution_request(
    *,
    finding: dict,
    snapshot: dict,
    plan: dict,
    exploit_test: dict,
    preconditions: list[dict],
    timeout_seconds: int = 180,
    max_steps: int = 50_000,
) -> dict:
    """Build a deterministic request; no process or transaction is started."""
    normalized_snapshot = _normalize_snapshot(snapshot)
    try:
        validated_plan = validate_fork_execution_plan(plan, normalized_snapshot)
    except (ForkExecutionPlanError, TypeError, ValueError) as exc:
        raise FindingExecutionContractError("fork_plan_invalid") from exc
    normalized_finding = _normalize_finding(finding)
    if normalized_finding["contract_address"] != normalized_snapshot["contract_address"]:
        raise FindingExecutionContractError("finding_snapshot_contract_mismatch")
    if (
        normalized_finding["commit_sha"] == ""
        or not _is_int(timeout_seconds, minimum=1, maximum=_MAX_TIMEOUT_SECONDS)
        or not _is_int(max_steps, minimum=1, maximum=_MAX_STEPS)
    ):
        raise FindingExecutionContractError("execution_limits_invalid")
    normalized_exploit = _normalize_exploit_test(exploit_test)
    normalized_preconditions = _normalize_preconditions(preconditions)
    return _build_request(
        finding=normalized_finding,
        snapshot=normalized_snapshot,
        plan=validated_plan,
        exploit_test=normalized_exploit,
        preconditions=normalized_preconditions,
        timeout_seconds=timeout_seconds,
        max_steps=max_steps,
    )


def validate_finding_execution_request(
    request: object, *, snapshot: dict, plan: dict
) -> dict:
    """Recompute every identity and policy field; reject all extra fields."""
    if not isinstance(request, dict) or set(request) != _REQUEST_FIELDS:
        raise FindingExecutionContractError("request_schema_invalid")
    if request.get("schema") != REQUEST_SCHEMA:
        raise FindingExecutionContractError("request_schema_invalid")
    normalized_snapshot = _normalize_snapshot(snapshot)
    try:
        validated_plan = validate_fork_execution_plan(plan, normalized_snapshot)
    except (ForkExecutionPlanError, TypeError, ValueError) as exc:
        raise FindingExecutionContractError("fork_plan_invalid") from exc

    finding = _normalize_finding(request.get("finding"))
    exploit_test = _normalize_exploit_test(request.get("exploit_test"))
    preconditions = _normalize_preconditions(request.get("preconditions"))
    execution = request.get("execution")
    if not isinstance(execution, dict) or set(execution) != {
        "runtime_profile", "timeout_seconds", "max_steps", "network_access",
        "external_transactions_enabled", "local_fork_transactions_enabled",
        "arbitrary_shell_enabled", "arbitrary_test_path_enabled",
    }:
        raise FindingExecutionContractError("execution_policy_invalid")
    expected = _build_request(
        finding=finding,
        snapshot=normalized_snapshot,
        plan=validated_plan,
        exploit_test=exploit_test,
        preconditions=preconditions,
        timeout_seconds=execution.get("timeout_seconds"),
        max_steps=execution.get("max_steps"),
    )
    if request != expected:
        raise FindingExecutionContractError("request_binding_or_policy_mismatch")
    return expected
