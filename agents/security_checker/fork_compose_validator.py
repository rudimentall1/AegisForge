"""Strict, side-effect-free validation of the AegisForge Anvil Compose topology.

This validates the repository's supported Compose contract. It does not ask
Docker to resolve interpolation, create networks, start containers, or attest
the host firewall or effective packet paths.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

import yaml


COMPOSE_SCHEMA_NAME = "aegisforge-anvil-fork"
SIDECAR_IMAGE = "aegisforge-rpc-sidecar:local"
ANVIL_CHAIN_ID_VARIABLE = (
    "${AEGISFORGE_ANVIL_CHAIN_ID:?Set the explicit fork chain ID from the execution plan}"
)
ANVIL_FORK_BLOCK_VARIABLE = (
    "${AEGISFORGE_ANVIL_FORK_BLOCK_NUMBER:?Set an exact fork block number}"
)
FOUNDRY_IMAGE_VARIABLE = (
    "${AEGISFORGE_FOUNDRY_IMAGE:?Set AEGISFORGE_FOUNDRY_IMAGE to an immutable Foundry image digest}"
)
GATEWAY_URL_VARIABLE = (
    "${AEGISFORGE_RPC_GATEWAY_UPSTREAM_URL:?Set the approved HTTPS RPC URL}"
)
GATEWAY_HOSTS_VARIABLE = (
    "${AEGISFORGE_RPC_GATEWAY_ALLOWED_HOSTS:?Set exact approved RPC DNS hosts}"
)
GATEWAY_TOKEN_VARIABLE = (
    "${AEGISFORGE_RPC_GATEWAY_TOKEN:?Set a random gateway bearer token}"
)

_SERVICE_KEYS = {
    "rpc-gateway": {
        "image", "environment", "networks", "read_only", "tmpfs",
        "cap_drop", "security_opt", "pids_limit", "mem_limit", "cpus",
        "healthcheck",
    },
    "anvil-rpc-adapter": {
        "image", "entrypoint", "environment", "depends_on", "networks",
        "read_only", "tmpfs", "cap_drop", "security_opt", "pids_limit",
        "mem_limit", "cpus", "healthcheck",
    },
    "anvil": {
        "image", "entrypoint", "command", "depends_on", "networks",
        "read_only", "tmpfs", "cap_drop", "security_opt", "pids_limit",
        "mem_limit", "cpus",
    },
}
_EXPECTED_GATEWAY_ENV = {
    "AEGISFORGE_RPC_GATEWAY_UPSTREAM_URL": GATEWAY_URL_VARIABLE,
    "AEGISFORGE_RPC_GATEWAY_ALLOWED_HOSTS": GATEWAY_HOSTS_VARIABLE,
    "AEGISFORGE_RPC_GATEWAY_TOKEN": GATEWAY_TOKEN_VARIABLE,
    "AEGISFORGE_RPC_GATEWAY_BIND_HOST": "0.0.0.0",
    "AEGISFORGE_RPC_GATEWAY_PORT": "8545",
}
_EXPECTED_ADAPTER_ENV = {
    "AEGISFORGE_ANVIL_GATEWAY_URL": "http://rpc-gateway:8545/rpc",
    "AEGISFORGE_ANVIL_GATEWAY_TOKEN": GATEWAY_TOKEN_VARIABLE,
    "AEGISFORGE_ANVIL_ADAPTER_BIND_HOST": "0.0.0.0",
    "AEGISFORGE_ANVIL_ADAPTER_PORT": "8546",
}
_EXPECTED_ANVIL_COMMAND = [
    "--host", "0.0.0.0",
    "--port", "8545",
    "--chain-id", ANVIL_CHAIN_ID_VARIABLE,
    "--fork-url", "http://anvil-rpc-adapter:8546",
    "--fork-block-number", ANVIL_FORK_BLOCK_VARIABLE,
]
_DIGEST_IMAGE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z")


class ComposeTopologyValidationError(ValueError):
    """Compose source does not satisfy the supported isolated-fork contract."""


@dataclass(frozen=True, slots=True)
class ComposeTopologyValidationReport:
    """Static validation receipt; it is not runtime or network evidence."""

    state: str
    services: tuple[str, ...]
    egress_service: str
    checked_invariants: tuple[str, ...]
    runtime_started: bool = False
    dynamic_verified: bool = False
    confirmed: bool = False


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise ComposeTopologyValidationError("compose_yaml_invalid") from exc
        if duplicate:
            raise ComposeTopologyValidationError("compose_yaml_invalid")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ComposeTopologyValidationError(reason)


def _is_mapping(value: object) -> bool:
    return isinstance(value, dict) and all(isinstance(key, str) for key in value)


def _validate_service_security(name: str, service: dict) -> None:
    _require(service.get("read_only") is True, f"{name}_read_only_required")
    _require(service.get("cap_drop") == ["ALL"], f"{name}_capabilities_invalid")
    _require(
        service.get("security_opt") == ["no-new-privileges:true"],
        f"{name}_security_options_invalid",
    )
    _require(
        isinstance(service.get("pids_limit"), int)
        and not isinstance(service.get("pids_limit"), bool)
        and service["pids_limit"] > 0,
        f"{name}_pids_limit_invalid",
    )
    _require(
        isinstance(service.get("mem_limit"), str)
        and re.fullmatch(r"[1-9][0-9]*(?:m|g)", service["mem_limit"]),
        f"{name}_memory_limit_invalid",
    )
    _require(
        isinstance(service.get("cpus"), (int, float))
        and not isinstance(service.get("cpus"), bool)
        and service["cpus"] > 0,
        f"{name}_cpu_limit_invalid",
    )
    tmpfs = service.get("tmpfs")
    _require(
        isinstance(tmpfs, list)
        and len(tmpfs) == 1
        and isinstance(tmpfs[0], str)
        and re.fullmatch(r"/tmp:rw,noexec,nosuid,size=[1-9][0-9]*m", tmpfs[0]),
        f"{name}_tmpfs_invalid",
    )


def validate_anvil_fork_compose(source: str) -> ComposeTopologyValidationReport:
    """Validate the exact AegisForge Compose contract without side effects."""
    if not isinstance(source, str) or not source or len(source.encode("utf-8")) > 262144:
        raise ComposeTopologyValidationError("compose_source_invalid")

    try:
        document = yaml.load(source, Loader=_UniqueKeyLoader)
    except ComposeTopologyValidationError:
        raise
    except (yaml.YAMLError, UnicodeError, RecursionError, TypeError, ValueError) as exc:
        raise ComposeTopologyValidationError("compose_yaml_invalid") from exc

    _require(_is_mapping(document), "compose_document_invalid")
    _require(
        set(document) == {"name", "services", "networks"}
        and document.get("name") == COMPOSE_SCHEMA_NAME,
        "compose_root_schema_invalid",
    )

    services = document.get("services")
    _require(
        _is_mapping(services) and set(services) == set(_SERVICE_KEYS),
        "compose_services_invalid",
    )
    for name, allowed_keys in _SERVICE_KEYS.items():
        service = services[name]
        _require(_is_mapping(service), f"{name}_service_invalid")
        _require(set(service).issubset(allowed_keys), f"{name}_service_fields_invalid")
        _require("ports" not in service, "published_ports_forbidden")
        _validate_service_security(name, service)

    gateway = services["rpc-gateway"]
    adapter = services["anvil-rpc-adapter"]
    anvil = services["anvil"]

    _require(gateway.get("image") == SIDECAR_IMAGE, "gateway_image_invalid")
    _require(adapter.get("image") == SIDECAR_IMAGE, "adapter_image_invalid")
    _require(
        gateway.get("environment") == _EXPECTED_GATEWAY_ENV,
        "gateway_environment_invalid",
    )
    _require(
        adapter.get("environment") == _EXPECTED_ADAPTER_ENV,
        "adapter_environment_invalid",
    )
    _require(
        adapter.get("entrypoint")
        == ["python", "-m", "agents.security_checker.anvil_rpc_adapter"],
        "adapter_entrypoint_invalid",
    )
    _require(
        anvil.get("image") == FOUNDRY_IMAGE_VARIABLE
        and isinstance(anvil.get("image"), str),
        "foundry_image_reference_invalid",
    )
    _require(
        isinstance(anvil.get("image"), str)
        and anvil["image"] == FOUNDRY_IMAGE_VARIABLE,
        "foundry_image_reference_invalid",
    )
    _require(
        _DIGEST_IMAGE.fullmatch("foundry@sha256:" + "0" * 64) is not None,
        "validator_digest_rule_invalid",
    )
    _require(
        anvil.get("entrypoint") == ["anvil"]
        and anvil.get("command") == _EXPECTED_ANVIL_COMMAND,
        "anvil_fork_identity_invalid",
    )
    _require(
        "environment" not in anvil,
        "anvil_environment_invalid",
    )

    _require(
        gateway.get("networks")
        == {
            "fork-internal": {"aliases": ["rpc-gateway"]},
            "rpc-egress": {"ipv4_address": "172.31.240.2", "gw_priority": 1},
        },
        "gateway_network_boundary_invalid",
    )
    _require(
        adapter.get("networks") == ["fork-internal"],
        "adapter_network_boundary_invalid",
    )
    _require(
        anvil.get("networks") == ["fork-internal"],
        "anvil_network_boundary_invalid",
    )
    _require(
        adapter.get("depends_on")
        == {"rpc-gateway": {"condition": "service_healthy"}},
        "adapter_dependency_invalid",
    )
    _require(
        anvil.get("depends_on")
        == {"anvil-rpc-adapter": {"condition": "service_healthy"}},
        "anvil_dependency_invalid",
    )

    networks = document.get("networks")
    _require(
        _is_mapping(networks)
        and set(networks) == {"fork-internal", "rpc-egress"},
        "compose_networks_invalid",
    )
    internal = networks["fork-internal"]
    egress = networks["rpc-egress"]
    _require(
        _is_mapping(internal)
        and internal.get("internal") is True
        and internal.get("enable_ipv6") is False
        and internal.get("ipam", {}).get("config")
        == [{"subnet": "172.30.240.0/24"}]
        and set(internal) == {"internal", "enable_ipv6", "ipam"},
        "fork_internal_network_invalid",
    )
    _require(
        _is_mapping(egress)
        and egress.get("driver") == "bridge"
        and egress.get("enable_ipv6") is False
        and egress.get("driver_opts")
        == {
            "com.docker.network.bridge.name": "br-aegisforge",
            "com.docker.network.bridge.enable_icc": "false",
        }
        and egress.get("ipam", {}).get("config")
        == [{"subnet": "172.31.240.0/28"}]
        and set(egress) == {"driver", "enable_ipv6", "driver_opts", "ipam"},
        "rpc_egress_network_invalid",
    )

    for name, service in (("rpc-gateway", gateway), ("anvil-rpc-adapter", adapter)):
        healthcheck = service.get("healthcheck")
        _require(
            _is_mapping(healthcheck)
            and isinstance(healthcheck.get("test"), list)
            and healthcheck["test"][:2] == ["CMD", "python"]
            and healthcheck.get("interval") == "5s"
            and healthcheck.get("timeout") == "3s"
            and healthcheck.get("retries") == 12
            and healthcheck.get("start_period") == "3s"
            and set(healthcheck)
            == {"test", "interval", "timeout", "retries", "start_period"},
            f"{name}_healthcheck_invalid",
        )

    return ComposeTopologyValidationReport(
        state="STATIC_VALIDATED",
        services=("rpc-gateway", "anvil-rpc-adapter", "anvil"),
        egress_service="rpc-gateway",
        checked_invariants=(
            "strict_yaml_without_duplicate_keys",
            "exact_service_inventory",
            "single_egress_gateway",
            "internal_only_adapter_and_anvil",
            "no_published_ports",
            "explicit_chain_and_block_anchors",
            "digest_pinned_foundry_reference",
            "read_only_container_security",
            "bounded_container_resources",
            "gateway_and_adapter_health_dependencies",
            "ipv6_disabled_networks",
            "dedicated_egress_bridge",
        ),
    )
