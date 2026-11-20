"""Strict, side-effect-free validation of the AegisForge Anvil Compose topology.

This validates the repository's supported Compose contract. It does not ask
Docker to resolve interpolation, create networks, start containers, or attest
the host firewall or effective packet paths.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from urllib.parse import urlsplit

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


def _resolved_dependency_matches(value: object, service_name: str) -> bool:
    if not _is_mapping(value):
        return False
    if set(value) not in (
        {"condition"},
        {"condition", "required"},
        {"condition", "required", "restart"},
    ):
        return False
    return (
        value.get("condition") == "service_healthy"
        and value.get("required", True) is True
        and value.get("restart", False) is False
    )


def _validate_service_security(name: str, service: dict) -> None:
    limits = {
        "rpc-gateway": (64, "256m", 1.0, "/tmp:rw,noexec,nosuid,size=16m"),
        "anvil-rpc-adapter": (64, "256m", 1.0, "/tmp:rw,noexec,nosuid,size=16m"),
        "anvil": (128, "1g", 2.0, "/tmp:rw,noexec,nosuid,size=64m"),
    }
    expected_pids, expected_memory, expected_cpus, expected_tmpfs = limits[name]
    _require(service.get("read_only") is True, f"{name}_read_only_required")
    _require(service.get("cap_drop") == ["ALL"], f"{name}_capabilities_invalid")
    _require(
        service.get("security_opt") == ["no-new-privileges:true"],
        f"{name}_security_options_invalid",
    )
    _require(
        service.get("pids_limit") == expected_pids
        and not isinstance(service.get("pids_limit"), bool),
        f"{name}_pids_limit_invalid",
    )
    memory_bytes = {
        "256m": "268435456",
        "1g": "1073741824",
    }[expected_memory]
    _require(
        service.get("mem_limit") in {expected_memory, memory_bytes},
        f"{name}_memory_limit_invalid",
    )
    _require(
        service.get("cpus") == expected_cpus
        and not isinstance(service.get("cpus"), bool),
        f"{name}_cpu_limit_invalid",
    )
    tmpfs_bytes = {
        "/tmp:rw,noexec,nosuid,size=16m": "/tmp:rw,noexec,nosuid,size=16777216",
        "/tmp:rw,noexec,nosuid,size=64m": "/tmp:rw,noexec,nosuid,size=67108864",
    }[expected_tmpfs]
    _require(
        service.get("tmpfs") in ([expected_tmpfs], [tmpfs_bytes]),
        f"{name}_tmpfs_invalid",
    )


def validate_anvil_fork_compose(
    source: str,
    *,
    foundry_image: str,
) -> ComposeTopologyValidationReport:
    """Validate Compose source and the resolved digest-pinned Foundry image."""

    if not isinstance(source, str) or not source:
        raise ComposeTopologyValidationError("compose_source_invalid")
    try:
        source_size = len(source.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ComposeTopologyValidationError("compose_source_invalid") from exc
    if source_size > 262144:
        raise ComposeTopologyValidationError("compose_source_invalid")
    if not isinstance(foundry_image, str) or not _DIGEST_IMAGE.fullmatch(foundry_image):
        raise ComposeTopologyValidationError("foundry_image_not_digest_pinned")

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
        _require("ports" not in service, "published_ports_forbidden")
        if name == "anvil":
            _require("environment" not in service, "anvil_environment_invalid")
        _require(set(service).issubset(allowed_keys), f"{name}_service_fields_invalid")
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
        anvil.get("image") == FOUNDRY_IMAGE_VARIABLE,
        "foundry_image_reference_invalid",
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

    gateway_networks = gateway.get("networks")
    _require(
        _is_mapping(gateway_networks)
        and set(gateway_networks) == {"fork-internal", "rpc-egress"},
        "gateway_network_boundary_invalid",
    )
    _require(
        _is_mapping(gateway_networks["rpc-egress"])
        and gateway_networks["rpc-egress"].get("gw_priority") == 1,
        "gateway_egress_route_invalid",
    )
    _require(
        gateway_networks
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
        and _is_mapping(internal.get("ipam"))
        and internal["ipam"].get("config") == [{"subnet": "172.30.240.0/24"}]
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
        and _is_mapping(egress.get("ipam"))
        and egress["ipam"].get("config") == [{"subnet": "172.31.240.0/28"}]
        and set(egress) == {"driver", "enable_ipv6", "driver_opts", "ipam"},
        "rpc_egress_network_invalid",
    )

    expected_healthchecks = {
        "rpc-gateway": [
            "CMD", "python", "-c",
            "import socket; s=socket.create_connection(('127.0.0.1',8545),2); s.close()",
        ],
        "anvil-rpc-adapter": [
            "CMD", "python", "-c",
            "import socket; s=socket.create_connection(('127.0.0.1',8546),2); s.close()",
        ],
    }
    for name, service in (("rpc-gateway", gateway), ("anvil-rpc-adapter", adapter)):
        healthcheck = service.get("healthcheck")
        _require(
            _is_mapping(healthcheck)
            and healthcheck.get("test") == expected_healthchecks[name]
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



def validate_resolved_anvil_fork_compose(
    resolved: object,
    *,
    expected_runtime: object,
) -> ComposeTopologyValidationReport:
    """Validate effective Compose JSON after variable interpolation.

    The caller must obtain the mapping from docker compose config --format
    json. This function performs no subprocess or Docker calls. Secret values
    are compared in memory and never copied into the report.
    """
    expected_fields = {
        "upstream_url",
        "allowed_hosts",
        "bearer_token",
        "foundry_image",
        "fork_chain_id",
        "fork_block_number",
    }
    _require(_is_mapping(expected_runtime), "resolved_runtime_expectations_invalid")
    _require(
        set(expected_runtime) == expected_fields,
        "resolved_runtime_expectations_invalid",
    )

    upstream_url = expected_runtime["upstream_url"]
    allowed_hosts = expected_runtime["allowed_hosts"]
    bearer_token = expected_runtime["bearer_token"]
    foundry_image = expected_runtime["foundry_image"]
    chain_id = expected_runtime["fork_chain_id"]
    block_number = expected_runtime["fork_block_number"]
    _require(
        isinstance(upstream_url, str) and upstream_url.startswith("https://"),
        "resolved_runtime_expectations_invalid",
    )
    _require(
        isinstance(allowed_hosts, (list, tuple, set, frozenset))
        and bool(allowed_hosts)
        and all(
            isinstance(host, str)
            and host
            and host == host.strip()
            and "/" not in host
            and "*" not in host
            for host in allowed_hosts
        ),
        "resolved_runtime_expectations_invalid",
    )
    try:
        parsed_upstream = urlsplit(upstream_url)
        upstream_port = parsed_upstream.port
    except ValueError as exc:
        raise ComposeTopologyValidationError(
            "resolved_runtime_expectations_invalid"
        ) from exc
    normalized_hosts = {host.lower().rstrip(".") for host in allowed_hosts}
    _require(
        parsed_upstream.scheme == "https"
        and parsed_upstream.hostname is not None
        and parsed_upstream.hostname.lower().rstrip(".") in normalized_hosts
        and parsed_upstream.username is None
        and parsed_upstream.password is None
        and upstream_port in (None, 443)
        and not parsed_upstream.fragment,
        "resolved_runtime_expectations_invalid",
    )
    _require(
        isinstance(bearer_token, str) and len(bearer_token) >= 32,
        "resolved_runtime_expectations_invalid",
    )
    _require(
        isinstance(foundry_image, str) and _DIGEST_IMAGE.fullmatch(foundry_image),
        "foundry_image_not_digest_pinned",
    )
    _require(
        isinstance(chain_id, int) and not isinstance(chain_id, bool) and chain_id > 0,
        "resolved_runtime_expectations_invalid",
    )
    _require(
        isinstance(block_number, int)
        and not isinstance(block_number, bool)
        and block_number >= 0,
        "resolved_runtime_expectations_invalid",
    )

    _require(_is_mapping(resolved), "resolved_compose_document_invalid")
    _require(
        resolved.get("name") == COMPOSE_SCHEMA_NAME
        and _is_mapping(resolved.get("services"))
        and _is_mapping(resolved.get("networks")),
        "resolved_compose_document_invalid",
    )
    services = resolved["services"]
    networks = resolved["networks"]
    _require(
        set(services) == set(_SERVICE_KEYS),
        "resolved_compose_services_invalid",
    )
    _require(
        set(networks) == {"fork-internal", "rpc-egress"},
        "resolved_compose_networks_invalid",
    )

    forbidden_service_fields = {
        "privileged", "network_mode", "devices", "cap_add", "volumes",
        "volumes_from", "pid", "ipc", "userns_mode", "runtime", "sysctls",
        "dns", "extra_hosts", "use_api_socket",
    }
    for name, service in services.items():
        _require(_is_mapping(service), "resolved_compose_service_invalid")
        _require(
            not forbidden_service_fields.intersection(service),
            "resolved_privileged_mode_forbidden",
        )
        _require("ports" not in service, "resolved_published_ports_forbidden")
        _require(
            set(service) == _SERVICE_KEYS[name],
            "resolved_compose_service_fields_invalid",
        )
        _validate_service_security(name, service)

    gateway = services["rpc-gateway"]
    adapter = services["anvil-rpc-adapter"]
    anvil = services["anvil"]

    _require(
        gateway.get("image") == SIDECAR_IMAGE
        and adapter.get("image") == SIDECAR_IMAGE,
        "resolved_sidecar_image_invalid",
    )
    _require(
        anvil.get("image") == foundry_image,
        "resolved_foundry_image_mismatch",
    )

    expected_hosts_value = ",".join(sorted(set(allowed_hosts)))
    expected_gateway_environment = {
        "AEGISFORGE_RPC_GATEWAY_UPSTREAM_URL": upstream_url,
        "AEGISFORGE_RPC_GATEWAY_ALLOWED_HOSTS": expected_hosts_value,
        "AEGISFORGE_RPC_GATEWAY_TOKEN": bearer_token,
        "AEGISFORGE_RPC_GATEWAY_BIND_HOST": "0.0.0.0",
        "AEGISFORGE_RPC_GATEWAY_PORT": "8545",
    }
    expected_adapter_environment = {
        "AEGISFORGE_ANVIL_GATEWAY_URL": "http://rpc-gateway:8545/rpc",
        "AEGISFORGE_ANVIL_GATEWAY_TOKEN": bearer_token,
        "AEGISFORGE_ANVIL_ADAPTER_BIND_HOST": "0.0.0.0",
        "AEGISFORGE_ANVIL_ADAPTER_PORT": "8546",
    }
    _require(
        gateway.get("environment") == expected_gateway_environment,
        "resolved_gateway_environment_invalid",
    )
    _require(
        adapter.get("environment") == expected_adapter_environment,
        "resolved_gateway_secret_mismatch",
    )
    _require(
        "environment" not in anvil,
        "resolved_anvil_environment_invalid",
    )

    expected_command = [
        "--host", "0.0.0.0",
        "--port", "8545",
        "--chain-id", str(chain_id),
        "--fork-url", "http://anvil-rpc-adapter:8546",
        "--fork-block-number", str(block_number),
    ]
    _require(
        anvil.get("entrypoint") == ["anvil"]
        and anvil.get("command") == expected_command,
        "resolved_anvil_fork_identity_invalid",
    )
    _require(
        adapter.get("entrypoint")
        == ["python", "-m", "agents.security_checker.anvil_rpc_adapter"],
        "resolved_adapter_entrypoint_invalid",
    )

    _require(
        _is_mapping(gateway.get("networks"))
        and set(gateway["networks"]) == {"fork-internal", "rpc-egress"}
        and _is_mapping(gateway["networks"]["rpc-egress"])
        and gateway["networks"]["rpc-egress"].get("gw_priority") == 1
        and gateway["networks"]["rpc-egress"].get("ipv4_address") == "172.31.240.2",
        "resolved_gateway_network_boundary_invalid",
    )
    _require(
        _is_mapping(adapter.get("networks"))
        and set(adapter["networks"]) == {"fork-internal"},
        "resolved_adapter_network_boundary_invalid",
    )
    _require(
        _is_mapping(anvil.get("networks"))
        and set(anvil["networks"]) == {"fork-internal"},
        "resolved_anvil_network_boundary_invalid",
    )

    internal = networks["fork-internal"]
    egress = networks["rpc-egress"]
    _require(
        _is_mapping(internal)
        and set(internal) in (
            {"internal", "enable_ipv6", "ipam"},
            {"internal", "enable_ipv6", "ipam", "name"},
        )
        and (
            "name" not in internal
            or internal.get("name") == "aegisforge-anvil-fork_fork-internal"
        )
        and internal.get("internal") is True
        and internal.get("enable_ipv6") is False
        and _is_mapping(internal.get("ipam"))
        and isinstance(internal["ipam"].get("config"), list)
        and bool(internal["ipam"]["config"])
        and internal["ipam"]["config"][0].get("subnet") == "172.30.240.0/24",
        "resolved_fork_internal_network_invalid",
    )
    _require(
        _is_mapping(egress)
        and set(egress) in (
            {"driver", "enable_ipv6", "driver_opts", "ipam"},
            {"driver", "enable_ipv6", "driver_opts", "ipam", "name"},
        )
        and (
            "name" not in egress
            or egress.get("name") == "aegisforge-anvil-fork_rpc-egress"
        )
        and egress.get("driver") == "bridge"
        and egress.get("enable_ipv6") is False
        and _is_mapping(egress.get("driver_opts"))
        and egress["driver_opts"].get("com.docker.network.bridge.name")
        == "br-aegisforge"
        and egress["driver_opts"].get("com.docker.network.bridge.enable_icc")
        == "false"
        and _is_mapping(egress.get("ipam"))
        and isinstance(egress["ipam"].get("config"), list)
        and bool(egress["ipam"]["config"])
        and egress["ipam"]["config"][0].get("subnet") == "172.31.240.0/28",
        "resolved_rpc_egress_network_invalid",
    )

    adapter_dependencies = adapter.get("depends_on")
    anvil_dependencies = anvil.get("depends_on")
    _require(
        _is_mapping(adapter_dependencies)
        and set(adapter_dependencies) == {"rpc-gateway"}
        and _resolved_dependency_matches(
            adapter_dependencies["rpc-gateway"], "rpc-gateway"
        )
        and _is_mapping(anvil_dependencies)
        and set(anvil_dependencies) == {"anvil-rpc-adapter"}
        and _resolved_dependency_matches(
            anvil_dependencies["anvil-rpc-adapter"], "anvil-rpc-adapter"
        ),
        "resolved_service_dependency_invalid",
    )
    expected_healthchecks = {
        "rpc-gateway": [
            "CMD", "python", "-c",
            "import socket; s=socket.create_connection(('127.0.0.1',8545),2); s.close()",
        ],
        "anvil-rpc-adapter": [
            "CMD", "python", "-c",
            "import socket; s=socket.create_connection(('127.0.0.1',8546),2); s.close()",
        ],
    }
    for name, service in (("rpc-gateway", gateway), ("anvil-rpc-adapter", adapter)):
        healthcheck = service.get("healthcheck")
        _require(
            _is_mapping(healthcheck)
            and healthcheck.get("test") == expected_healthchecks[name]
            and healthcheck.get("interval") == "5s"
            and healthcheck.get("timeout") == "3s"
            and healthcheck.get("retries") == 12
            and healthcheck.get("start_period") == "3s",
            "resolved_healthcheck_invalid",
        )

    return ComposeTopologyValidationReport(
        state="RESOLVED_STATIC_VALIDATED",
        services=("rpc-gateway", "anvil-rpc-adapter", "anvil"),
        egress_service="rpc-gateway",
        checked_invariants=(
            "resolved_service_inventory",
            "resolved_secret_consistency",
            "resolved_provider_host_configuration",
            "resolved_digest_pinned_foundry_image",
            "resolved_chain_and_block_anchors",
            "resolved_single_egress_gateway",
            "resolved_internal_only_adapter_and_anvil",
            "resolved_no_published_ports",
            "resolved_read_only_container_security",
            "resolved_bounded_container_resources",
        ),
    )
