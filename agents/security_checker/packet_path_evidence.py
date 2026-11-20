"""Fail-closed validation for disposable Docker packet-path evidence receipts.

A valid receipt proves only that a specific CI run recorded the declared probes
and counter deltas. It is not finding-specific exploit evidence and never
promotes runtime isolation, dynamic verification, or vulnerability confirmation.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping
from uuid import UUID


_PROJECT = "aegisforge-anvil-fork"
_SERVICES = ("rpc-gateway", "anvil-rpc-adapter", "anvil")
_NETWORK_NAMES = {
    "fork-internal": f"{_PROJECT}_fork-internal",
    "rpc-egress": f"{_PROJECT}_rpc-egress",
}
_COUNTERS = (
    "gateway_approved_egress_allow_new",
    "gateway_unapproved_egress_drop",
)
_PROBES = {
    "gateway_approved_egress": ("attempted", "rule_matched"),
    "gateway_unapproved_egress": ("attempted", "blocked", "rule_matched"),
    "adapter_gateway_internal": ("connected",),
    "anvil_adapter_internal": ("connected",),
    "adapter_external_egress": (
        "blocked",
        "default_route_absent",
        "internal_network_only",
    ),
    "anvil_external_egress": (
        "blocked",
        "default_route_absent",
        "internal_network_only",
    ),
}


class PacketPathEvidenceError(ValueError):
    """A packet-path receipt is malformed, incomplete, or unbound to its CI run."""


@dataclass(frozen=True, slots=True)
class PacketPathEvidenceReport:
    """Validated disposable-CI evidence; deliberately not a security promotion."""

    state: str
    runtime_session_id: str
    services: tuple[str, ...]
    container_ids: tuple[str, ...]
    network_ids: tuple[str, ...]
    firewall_ruleset_sha256: str
    runtime_started: bool = True
    runtime_isolation_verified: bool = False
    dynamic_verified: bool = False
    confirmed: bool = False


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise PacketPathEvidenceError(reason)


def _is_mapping(value: object) -> bool:
    return isinstance(value, Mapping)


def _is_hex(value: object, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and re.fullmatch(r"[0-9a-f]+", value) is not None
    )


def _validate_counter(counter: object) -> None:
    _require(
        _is_mapping(counter) and set(counter) == {"before", "after"},
        "packet_path_counter_invalid",
    )
    before = counter.get("before")
    after = counter.get("after")
    _require(
        type(before) is int
        and type(after) is int
        and before >= 0
        and after > before,
        "packet_path_counter_delta_missing",
    )


def validate_packet_path_receipt(
    receipt: object,
    *,
    expected_commit_sha: str,
    expected_run_id: str,
    expected_run_attempt: int,
) -> PacketPathEvidenceReport:
    """Validate a receipt against the exact GitHub Actions execution context.

    This validates evidence structure and bindings only. It does not independently
    execute probes, inspect Docker, or promote any finding/security state.
    """
    _require(_is_hex(expected_commit_sha, 40), "packet_path_commit_binding_invalid")
    _require(
        isinstance(expected_run_id, str)
        and expected_run_id.isdigit()
        and int(expected_run_id) > 0
        and type(expected_run_attempt) is int
        and expected_run_attempt > 0,
        "packet_path_run_binding_invalid",
    )
    _require(_is_mapping(receipt), "packet_path_receipt_invalid")

    required_fields = {
        "schema_version",
        "evidence_level",
        "runtime_session_id",
        "git_commit_sha",
        "github_run_id",
        "github_run_attempt",
        "containers",
        "networks",
        "firewall",
        "probes",
    }
    _require(set(receipt) == required_fields, "packet_path_receipt_schema_invalid")
    _require(
        type(receipt.get("schema_version")) is int
        and receipt.get("schema_version") == 1
        and receipt.get("evidence_level") == "DISPOSABLE_DOCKER_PACKET_PATH_TEST",
        "packet_path_receipt_schema_invalid",
    )

    session_id = receipt.get("runtime_session_id")
    try:
        canonical_session_id = str(UUID(session_id)) if isinstance(session_id, str) else ""
    except (ValueError, AttributeError, TypeError):
        canonical_session_id = ""
    _require(
        bool(canonical_session_id) and canonical_session_id == session_id,
        "packet_path_session_invalid",
    )

    _require(
        receipt.get("git_commit_sha") == expected_commit_sha,
        "packet_path_commit_binding_invalid",
    )
    _require(
        receipt.get("github_run_id") == expected_run_id
        and type(receipt.get("github_run_attempt")) is int
        and receipt.get("github_run_attempt") == expected_run_attempt,
        "packet_path_run_binding_invalid",
    )

    containers = receipt.get("containers")
    _require(
        _is_mapping(containers) and set(containers) == set(_SERVICES),
        "packet_path_service_inventory_invalid",
    )
    container_ids = tuple(containers[service] for service in _SERVICES)
    _require(
        all(_is_hex(item, 64) for item in container_ids)
        and len(set(container_ids)) == len(_SERVICES),
        "packet_path_container_id_invalid",
    )

    networks = receipt.get("networks")
    _require(
        _is_mapping(networks) and set(networks) == set(_NETWORK_NAMES),
        "packet_path_network_inventory_invalid",
    )
    network_ids = []
    for logical_name, expected_name in _NETWORK_NAMES.items():
        network = networks.get(logical_name)
        _require(
            _is_mapping(network) and set(network) == {"name", "id"}
            and network.get("name") == expected_name
            and _is_hex(network.get("id"), 64),
            "packet_path_network_binding_invalid",
        )
        network_ids.append(network["id"])
    _require(len(set(network_ids)) == len(network_ids), "packet_path_network_binding_invalid")

    firewall = receipt.get("firewall")
    _require(
        _is_mapping(firewall)
        and set(firewall) == {"table", "ruleset_sha256", "counters"}
        and firewall.get("table") == "aegisforge_gateway_egress",
        "packet_path_firewall_identity_invalid",
    )
    _require(
        _is_hex(firewall.get("ruleset_sha256"), 64),
        "packet_path_ruleset_digest_invalid",
    )
    counters = firewall.get("counters")
    _require(
        _is_mapping(counters) and set(counters) == set(_COUNTERS),
        "packet_path_counter_inventory_invalid",
    )
    for counter_name in _COUNTERS:
        _validate_counter(counters[counter_name])

    probes = receipt.get("probes")
    _require(
        _is_mapping(probes) and set(probes) == set(_PROBES),
        "packet_path_probe_inventory_invalid",
    )
    for probe_name, required_results in _PROBES.items():
        probe = probes.get(probe_name)
        _require(
            _is_mapping(probe) and set(probe) == set(required_results)
            and all(probe.get(result_name) is True for result_name in required_results),
            "packet_path_probe_incomplete",
        )

    return PacketPathEvidenceReport(
        state="PACKET_PATH_RECEIPT_VALIDATED",
        runtime_session_id=session_id,
        services=_SERVICES,
        container_ids=container_ids,
        network_ids=tuple(network_ids),
        firewall_ruleset_sha256=firewall["ruleset_sha256"],
    )
