"""Fail-closed validation of read-only Docker runtime observations.

This module validates Docker inspect/network inspect data and the presence of
the dedicated nftables table. It deliberately does not attest packet flow:
only an isolated packet-path probe can establish that boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
import shutil
import subprocess
from typing import Mapping


_SERVICES = ("rpc-gateway", "anvil-rpc-adapter", "anvil")
_INTERNAL_NETWORK = "aegisforge-anvil-fork_fork-internal"
_EGRESS_NETWORK = "aegisforge-anvil-fork_rpc-egress"
_FIREWALL_TABLE = "aegisforge_gateway_egress"


class RuntimeEvidenceError(ValueError):
    """Runtime observations do not satisfy the supported fork topology."""


@dataclass(frozen=True, slots=True)
class RuntimeEvidenceReport:
    """Receipt for inspected runtime state, not packet-path verification."""

    state: str
    services: tuple[str, ...]
    container_ids: tuple[str, ...]
    networks: tuple[str, ...]
    firewall_table: str
    runtime_started: bool = True
    runtime_isolation_verified: bool = False
    dynamic_verified: bool = False
    confirmed: bool = False


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise RuntimeEvidenceError(reason)


def _mapping(value: object) -> bool:
    return isinstance(value, Mapping)


def _labels(value: object) -> Mapping:
    return value if _mapping(value) else {}


def _validate_container(container: object, *, project: str, service: str) -> str:
    _require(_mapping(container), "runtime_container_invalid")
    config = container.get("Config")
    _require(_mapping(config), "runtime_container_invalid")
    labels = _labels(config.get("Labels"))
    image = config.get("Image")
    if service == "anvil":
        digest = image.rsplit("@sha256:", 1)[1] if isinstance(image, str) and "@sha256:" in image else ""
        _require(
            len(digest) == 64 and all(char in "0123456789abcdef" for char in digest),
            "runtime_image_identity_invalid",
        )
        _require(config.get("Entrypoint") == ["anvil"], "runtime_process_identity_invalid")
    else:
        expected_entrypoint = (
            ["python", "-m", "agents.security_checker.rpc_gateway"]
            if service == "rpc-gateway"
            else ["python", "-m", "agents.security_checker.anvil_rpc_adapter"]
        )
        _require(
            image == "aegisforge-rpc-sidecar:local"
            and config.get("Entrypoint") == expected_entrypoint,
            "runtime_process_identity_invalid",
        )
    _require(
        labels.get("com.docker.compose.project") == project
        and labels.get("com.docker.compose.service") == service,
        "runtime_project_binding_invalid",
    )

    container_id = container.get("Id")
    _require(
        isinstance(container_id, str)
        and len(container_id) == 64
        and all(char in "0123456789abcdef" for char in container_id.lower()),
        "runtime_container_id_invalid",
    )

    state = container.get("State")
    _require(
        _mapping(state) and state.get("Running") is True and state.get("Status") == "running",
        "runtime_service_not_running",
    )
    if service in {"rpc-gateway", "anvil-rpc-adapter"}:
        health = state.get("Health")
        _require(
            _mapping(health) and health.get("Status") == "healthy",
            "runtime_service_unhealthy",
        )

    host = container.get("HostConfig")
    _require(_mapping(host), "runtime_container_hardening_invalid")
    expected = {
        "rpc-gateway": (64, 268435456, 1_000_000_000),
        "anvil-rpc-adapter": (64, 268435456, 1_000_000_000),
        "anvil": (128, 1_073_741_824, 2_000_000_000),
    }[service]
    _require(
        host.get("ReadonlyRootfs") is True
        and host.get("CapDrop") == ["ALL"]
        and host.get("SecurityOpt") == ["no-new-privileges:true"]
        and host.get("PidsLimit") == expected[0]
        and host.get("Memory") == expected[1]
        and host.get("NanoCpus") == expected[2]
        and host.get("Privileged") is False
        and host.get("PortBindings") in (None, {})
        and host.get("Binds") in (None, []),
        "runtime_container_hardening_invalid",
    )

    mounts = container.get("Mounts")
    _require(isinstance(mounts, list), "runtime_mounts_invalid")
    _require(
        all(
            _mapping(mount)
            and mount.get("Type") == "tmpfs"
            and mount.get("Destination") == "/tmp"
            and mount.get("RW") is True
            for mount in mounts
        )
        and len(mounts) == 1,
        "runtime_mounts_invalid",
    )

    network_settings = container.get("NetworkSettings")
    _require(_mapping(network_settings), "runtime_network_attachment_invalid")
    attached = network_settings.get("Networks")
    expected_networks = (
        {_INTERNAL_NETWORK, _EGRESS_NETWORK}
        if service == "rpc-gateway"
        else {_INTERNAL_NETWORK}
    )
    _require(
        _mapping(attached) and set(attached) == expected_networks,
        "runtime_network_attachment_invalid",
    )
    if service == "rpc-gateway":
        egress = attached.get(_EGRESS_NETWORK)
        _require(
            _mapping(egress) and egress.get("IPAddress") == "172.31.240.2",
            "runtime_gateway_egress_address_invalid",
        )
    return container_id


def _validate_network(network: object, *, project: str, logical_name: str) -> str:
    _require(_mapping(network), "runtime_network_topology_invalid")
    name = network.get("Name")
    expected_name = f"{project}_{logical_name}"
    labels = _labels(network.get("Labels"))
    _require(
        name == expected_name
        and labels.get("com.docker.compose.project") == project
        and labels.get("com.docker.compose.network") == logical_name,
        "runtime_network_topology_invalid",
    )
    internal = logical_name == "fork-internal"
    options = network.get("Options") or {}
    _require(_mapping(options), "runtime_network_topology_invalid")
    if internal:
        options_valid = (
            options.get("com.docker.network.bridge.enable_icc") != "false"
            and "com.docker.network.bridge.name" not in options
        )
    else:
        options_valid = (
            options.get("com.docker.network.bridge.enable_icc") == "false"
            and options.get("com.docker.network.bridge.name") == "br-aegisforge"
        )
    expected_subnet = "172.30.240.0/24" if internal else "172.31.240.0/28"
    ipam = network.get("IPAM")
    configs = ipam.get("Config") if _mapping(ipam) else None
    _require(
        network.get("Driver") == "bridge"
        and network.get("Internal") is internal
        and network.get("EnableIPv6") is False
        and options_valid
        and isinstance(configs, list)
        and len(configs) == 1
        and _mapping(configs[0])
        and configs[0].get("Subnet") == expected_subnet,
        "runtime_network_topology_invalid",
    )
    return name


def validate_runtime_observations(
    observations: object,
    *,
    expected_project: str,
) -> RuntimeEvidenceReport:
    """Validate Docker and nftables observations without claiming packet flow."""
    _require(
        isinstance(expected_project, str)
        and expected_project == "aegisforge-anvil-fork",
        "runtime_project_invalid",
    )
    _require(_mapping(observations), "runtime_observations_invalid")
    containers = observations.get("containers")
    networks = observations.get("networks")
    firewall = observations.get("firewall")
    _require(
        isinstance(containers, list)
        and len(containers) == len(_SERVICES)
        and isinstance(networks, list)
        and len(networks) == 2
        and _mapping(firewall),
        "runtime_service_inventory_invalid",
    )

    service_map = {}
    for container in containers:
        _require(_mapping(container), "runtime_container_invalid")
        config = container.get("Config")
        labels = _labels(config.get("Labels") if _mapping(config) else None)
        service = labels.get("com.docker.compose.service")
        _require(service in _SERVICES and service not in service_map, "runtime_service_inventory_invalid")
        service_map[service] = container
    _require(set(service_map) == set(_SERVICES), "runtime_service_inventory_invalid")

    container_ids = tuple(
        _validate_container(service_map[service], project=expected_project, service=service)
        for service in _SERVICES
    )
    _require(len(set(container_ids)) == len(_SERVICES), "runtime_container_id_invalid")

    network_map = {}
    for network in networks:
        _require(_mapping(network), "runtime_network_topology_invalid")
        name = network.get("Name")
        _require(name in {_INTERNAL_NETWORK, _EGRESS_NETWORK} and name not in network_map,
                 "runtime_network_topology_invalid")
        network_map[name] = network
    validated_networks = (
        _validate_network(network_map[_INTERNAL_NETWORK], project=expected_project, logical_name="fork-internal"),
        _validate_network(network_map[_EGRESS_NETWORK], project=expected_project, logical_name="rpc-egress"),
    )

    _require(
        firewall.get("table_present") is True
        and firewall.get("family") == "inet"
        and firewall.get("name") == _FIREWALL_TABLE,
        "runtime_firewall_table_missing",
    )

    return RuntimeEvidenceReport(
        state="RUNTIME_OBSERVATIONS_VALIDATED",
        services=_SERVICES,
        container_ids=container_ids,
        networks=validated_networks,
        firewall_table=_FIREWALL_TABLE,
    )



def _runtime_command(binary: str, args: list[str]) -> str:
    command = [binary, *args]
    try:
        result = subprocess.run(
            command,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=12,
            check=False,
            text=True,
            encoding="utf-8",
            errors="strict",
            env={
                "PATH": os.pathsep.join((os.path.dirname(binary), "/usr/bin", "/bin")),
                "HOME": "/nonexistent",
                "DOCKER_CONFIG": "/nonexistent",
            },
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise RuntimeEvidenceError("runtime_command_failed") from exc
    if result.returncode != 0:
        raise RuntimeEvidenceError("runtime_command_failed")
    output = result.stdout
    if not isinstance(output, str) or len(output.encode("utf-8")) > 2 * 1024 * 1024:
        raise RuntimeEvidenceError("runtime_command_output_invalid")
    return output


def _json_output(output: str, reason: str):
    try:
        return json.loads(output)
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError) as exc:
        raise RuntimeEvidenceError(reason) from exc


def collect_runtime_evidence(
    *,
    expected_project: str = "aegisforge-anvil-fork",
) -> RuntimeEvidenceReport:
    """Collect Docker inspect and nftables table observations without mutation.

    Only a compact validated receipt is returned. Raw inspect output can contain
    environment secrets and is intentionally kept local to this call.
    """
    _require(
        expected_project == "aegisforge-anvil-fork",
        "runtime_project_invalid",
    )
    docker = shutil.which("docker")
    nft = shutil.which("nft")
    _require(bool(docker) and bool(nft), "runtime_cli_unavailable")

    container_output = _runtime_command(
        docker,
        ["ps", "-aq", "--filter", f"label=com.docker.compose.project={expected_project}"],
    )
    container_ids = [line.strip() for line in container_output.splitlines() if line.strip()]
    _require(
        len(container_ids) == len(_SERVICES)
        and len(set(container_ids)) == len(_SERVICES)
        and all(
            len(item) == 64 and all(char in "0123456789abcdef" for char in item.lower())
            for item in container_ids
        ),
        "runtime_service_inventory_invalid",
    )
    containers = _json_output(
        _runtime_command(docker, ["inspect", *container_ids]),
        "runtime_container_inspect_invalid",
    )
    _require(isinstance(containers, list), "runtime_container_inspect_invalid")

    network_output = _runtime_command(
        docker,
        [
            "network", "ls", "--filter",
            f"label=com.docker.compose.project={expected_project}",
            "--format", "{{.Name}}",
        ],
    )
    network_names = [line.strip() for line in network_output.splitlines() if line.strip()]
    _require(
        len(network_names) == 2 and len(set(network_names)) == 2,
        "runtime_network_inventory_invalid",
    )
    networks = _json_output(
        _runtime_command(docker, ["network", "inspect", *network_names]),
        "runtime_network_inspect_invalid",
    )
    _require(isinstance(networks, list), "runtime_network_inspect_invalid")

    firewall_document = _json_output(
        _runtime_command(
            nft,
            ["-j", "list", "table", "inet", _FIREWALL_TABLE],
        ),
        "runtime_firewall_inspect_invalid",
    )
    _require(_mapping(firewall_document), "runtime_firewall_inspect_invalid")
    nftables = firewall_document.get("nftables")
    table_present = (
        isinstance(nftables, list)
        and any(
            _mapping(item)
            and _mapping(item.get("table"))
            and item["table"].get("family") == "inet"
            and item["table"].get("name") == _FIREWALL_TABLE
            for item in nftables
        )
    )

    return validate_runtime_observations(
        {
            "containers": containers,
            "networks": networks,
            "firewall": {
                "table_present": table_present,
                "family": "inet",
                "name": _FIREWALL_TABLE,
            },
        },
        expected_project=expected_project,
    )
