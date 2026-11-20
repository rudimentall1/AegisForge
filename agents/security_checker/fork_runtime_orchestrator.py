"""Preparation-only orchestration contract for isolated Anvil fork research.

This module validates inputs and emits a secret-free Compose environment. It
never starts containers, writes secret files, invokes a shell, or claims that
fork execution has occurred.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping
from urllib.parse import urlsplit

from agents.security_checker.anvil_rpc_adapter import (
    AnvilRpcAdapterError,
    build_gateway_headers,
)
from agents.security_checker.fork_execution_plan import (
    validate_fork_execution_plan,
)
from agents.security_checker.fork_compose_validator import (
    ComposeTopologyValidationError,
    ComposeTopologyValidationReport,
    validate_anvil_fork_compose,
)
from agents.security_checker.fork_engine import ForkSnapshotError
from agents.security_checker.rpc_gateway import RpcGatewayError, validate_upstream_url


_FOUNDRY_IMAGE_DIGEST_RE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z")
_REQUIRED_CONFIG_FIELDS = frozenset(
    {"upstream_url", "allowed_hosts", "bearer_token", "foundry_image"}
)
_REQUIRED_SECRET_INPUTS = (
    "AEGISFORGE_RPC_GATEWAY_UPSTREAM_URL",
    "AEGISFORGE_RPC_GATEWAY_ALLOWED_HOSTS",
    "AEGISFORGE_RPC_GATEWAY_TOKEN",
)


class ForkRuntimePreparationError(ValueError):
    """Runtime inputs are invalid; no runtime process has been started."""


@dataclass(frozen=True, slots=True)
class PreparedForkRuntime:
    """Secret-free, immutable description of a validated but unstarted runtime."""

    state: str
    snapshot_sha256: str
    fork_chain_id: int
    block_number: int
    network_profile: str
    compose_environment: tuple[tuple[str, str], ...]
    required_secret_inputs: tuple[str, ...]
    compose_validation: ComposeTopologyValidationReport
    runtime_started: bool = False
    dynamic_verified: bool = False
    confirmed: bool = False


def _validate_runtime_configuration(config: object) -> str:
    if not isinstance(config, Mapping) or set(config) != _REQUIRED_CONFIG_FIELDS:
        raise ForkRuntimePreparationError("runtime_configuration_fields_invalid")

    upstream_url = config.get("upstream_url")
    allowed_hosts = config.get("allowed_hosts")
    bearer_token = config.get("bearer_token")
    foundry_image = config.get("foundry_image")

    if (
        not isinstance(allowed_hosts, (list, tuple, set, frozenset))
        or not allowed_hosts
        or any(not isinstance(host, str) or not host.strip() for host in allowed_hosts)
    ):
        raise ForkRuntimePreparationError("upstream_configuration_invalid")

    try:
        normalized_url = validate_upstream_url(
            upstream_url,
            allowed_hosts=set(allowed_hosts),
        )
    except RpcGatewayError as exc:
        raise ForkRuntimePreparationError(str(exc)) from exc

    try:
        build_gateway_headers(bearer_token)
    except AnvilRpcAdapterError as exc:
        raise ForkRuntimePreparationError("gateway_token_invalid") from exc

    if (
        not isinstance(foundry_image, str)
        or not _FOUNDRY_IMAGE_DIGEST_RE.fullmatch(foundry_image)
    ):
        raise ForkRuntimePreparationError("foundry_image_not_digest_pinned")

    hostname = urlsplit(normalized_url).hostname
    if not hostname:
        raise ForkRuntimePreparationError("upstream_url_invalid")
    return hostname.lower().rstrip(".")


def prepare_fork_runtime(
    snapshot: dict,
    plan: object,
    runtime_config: Mapping[str, object],
    *,
    compose_source: str,
) -> PreparedForkRuntime:
    """Validate a fork plan and runtime config without starting any process.

    Secrets and the upstream URL are validated in-place and intentionally are
    not copied into the result, its repr, or the Compose environment. The
    caller must provide those values later through a separate secret channel.
    """
    try:
        validated_plan = validate_fork_execution_plan(plan, snapshot)
    except (ForkSnapshotError, ValueError, TypeError) as exc:
        reason = str(exc) if str(exc) else "fork_execution_plan_invalid"
        raise ForkRuntimePreparationError(reason) from exc

    _validate_runtime_configuration(runtime_config)
    try:
        compose_validation = validate_anvil_fork_compose(
            compose_source,
            foundry_image=runtime_config["foundry_image"],
        )
    except ComposeTopologyValidationError as exc:
        raise ForkRuntimePreparationError(str(exc)) from exc

    compose_environment = (
        ("AEGISFORGE_ANVIL_CHAIN_ID", str(validated_plan["fork_chain_id"])),
        ("AEGISFORGE_ANVIL_FORK_BLOCK_NUMBER", str(validated_plan["block_number"])),
        ("AEGISFORGE_FOUNDRY_IMAGE", runtime_config["foundry_image"]),
    )

    return PreparedForkRuntime(
        state="PREPARED",
        snapshot_sha256=validated_plan["snapshot_sha256"],
        fork_chain_id=validated_plan["fork_chain_id"],
        block_number=validated_plan["block_number"],
        network_profile=validated_plan["required_network_profile"],
        compose_environment=compose_environment,
        required_secret_inputs=_REQUIRED_SECRET_INPUTS,
        compose_validation=compose_validation,
    )
