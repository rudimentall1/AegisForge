"""Resolve and validate the effective Anvil Compose model without starting containers.

Only the repository-owned Compose file and a fixed Docker Compose config
command are accepted. Runtime secrets are supplied through a minimal child
environment, never through argv, a generated env file, stderr, or logs.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Mapping

from agents.security_checker.anvil_rpc_adapter import (
    AnvilRpcAdapterError,
    build_gateway_headers,
)
from agents.security_checker.fork_compose_validator import (
    ComposeTopologyValidationError,
    validate_anvil_fork_compose,
    validate_resolved_anvil_fork_compose,
)
from agents.security_checker.rpc_gateway import (
    RpcGatewayError,
    validate_upstream_url,
)


_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_COMPOSE_FILE = _REPOSITORY_ROOT / "deploy" / "anvil-fork" / "compose.yaml"
_REQUIRED_RUNTIME_FIELDS = frozenset(
    {"upstream_url", "allowed_hosts", "bearer_token", "foundry_image"}
)
_ENVIRONMENT_KEYS = frozenset(
    {
        "AEGISFORGE_RPC_GATEWAY_UPSTREAM_URL",
        "AEGISFORGE_RPC_GATEWAY_ALLOWED_HOSTS",
        "AEGISFORGE_RPC_GATEWAY_TOKEN",
        "AEGISFORGE_ANVIL_CHAIN_ID",
        "AEGISFORGE_ANVIL_FORK_BLOCK_NUMBER",
        "AEGISFORGE_FOUNDRY_IMAGE",
    }
)
_DIGEST_IMAGE = re.compile(r"[^\\s@]+@sha256:[0-9a-f]{64}\\Z")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\Z")
_MAX_CONFIG_OUTPUT_BYTES = 1_048_576
_CONFIG_TIMEOUT_SECONDS = 15


class ComposeConfigResolutionError(ValueError):
    """The fixed Compose config command failed or returned an invalid model."""


def _validated_environment(
    runtime_config: Mapping[str, object],
    *,
    fork_chain_id: int,
    fork_block_number: int,
) -> tuple[dict[str, str], tuple[str, ...]]:
    if not isinstance(runtime_config, Mapping) or set(runtime_config) != _REQUIRED_RUNTIME_FIELDS:
        raise ComposeConfigResolutionError("runtime_configuration_fields_invalid")

    upstream_url = runtime_config["upstream_url"]
    allowed_hosts = runtime_config["allowed_hosts"]
    bearer_token = runtime_config["bearer_token"]
    foundry_image = runtime_config["foundry_image"]

    if (
        not isinstance(allowed_hosts, (list, tuple, set, frozenset))
        or not allowed_hosts
        or any(
            not isinstance(host, str)
            or not host
            or host != host.strip()
            or host != host.lower()
            or host.endswith(".")
            or any(not _DNS_LABEL.fullmatch(label) for label in host.split("."))
            for host in allowed_hosts
        )
    ):
        raise ComposeConfigResolutionError("upstream_configuration_invalid")
    hosts = tuple(sorted(set(allowed_hosts)))

    try:
        validate_upstream_url(upstream_url, allowed_hosts=set(hosts))
    except (RpcGatewayError, TypeError) as exc:
        raise ComposeConfigResolutionError("upstream_configuration_invalid") from exc

    try:
        build_gateway_headers(bearer_token)
    except AnvilRpcAdapterError as exc:
        raise ComposeConfigResolutionError("gateway_token_invalid") from exc

    if not isinstance(foundry_image, str) or not _DIGEST_IMAGE.fullmatch(foundry_image):
        raise ComposeConfigResolutionError("foundry_image_not_digest_pinned")
    if (
        isinstance(fork_chain_id, bool)
        or not isinstance(fork_chain_id, int)
        or fork_chain_id <= 0
        or isinstance(fork_block_number, bool)
        or not isinstance(fork_block_number, int)
        or fork_block_number < 0
    ):
        raise ComposeConfigResolutionError("fork_identity_invalid")

    environment = {
        "AEGISFORGE_RPC_GATEWAY_UPSTREAM_URL": upstream_url,
        "AEGISFORGE_RPC_GATEWAY_ALLOWED_HOSTS": ",".join(hosts),
        "AEGISFORGE_RPC_GATEWAY_TOKEN": bearer_token,
        "AEGISFORGE_ANVIL_CHAIN_ID": str(fork_chain_id),
        "AEGISFORGE_ANVIL_FORK_BLOCK_NUMBER": str(fork_block_number),
        "AEGISFORGE_FOUNDRY_IMAGE": foundry_image,
    }
    return environment, hosts


def resolve_anvil_fork_compose(
    *,
    runtime_config: Mapping[str, object],
    fork_chain_id: int,
    fork_block_number: int,
) -> dict:
    """Run the fixed Docker Compose config command and validate its JSON output.

    This is configuration rendering only: no Docker daemon command, image
    pull, network creation, or container start is performed.
    """
    try:
        source = _COMPOSE_FILE.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ComposeConfigResolutionError("compose_source_unavailable") from exc

    environment, hosts = _validated_environment(
        runtime_config,
        fork_chain_id=fork_chain_id,
        fork_block_number=fork_block_number,
    )
    try:
        validate_anvil_fork_compose(
            source,
            foundry_image=runtime_config["foundry_image"],
        )
    except ComposeTopologyValidationError as exc:
        raise ComposeConfigResolutionError(str(exc)) from exc

    docker_path = shutil.which("docker")
    if not docker_path:
        raise ComposeConfigResolutionError("docker_cli_unavailable")
    docker_path = str(Path(docker_path).resolve())

    child_environment = {
        "PATH": os.pathsep.join((str(Path(docker_path).parent), os.defpath)),
        "HOME": "/nonexistent",
        "DOCKER_CONFIG": "/nonexistent",
        **environment,
    }
    if set(child_environment) - ({"PATH", "HOME", "DOCKER_CONFIG"} | _ENVIRONMENT_KEYS):
        raise ComposeConfigResolutionError("child_environment_invalid")

    command = [
        docker_path,
        "compose",
        "--env-file",
        os.devnull,
        "--project-directory",
        str(_REPOSITORY_ROOT),
        "--file",
        str(_COMPOSE_FILE),
        "config",
        "--format",
        "json",
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=str(_REPOSITORY_ROOT),
            env=child_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
            check=False,
            timeout=_CONFIG_TIMEOUT_SECONDS,
            text=True,
            encoding="utf-8",
            errors="strict",
        )
    except subprocess.TimeoutExpired as exc:
        raise ComposeConfigResolutionError("compose_config_timeout") from exc
    except (OSError, UnicodeError, ValueError) as exc:
        raise ComposeConfigResolutionError("compose_config_execution_failed") from exc

    if completed.returncode != 0:
        raise ComposeConfigResolutionError("compose_config_command_failed")
    if not isinstance(completed.stdout, str):
        raise ComposeConfigResolutionError("compose_config_output_invalid")
    if len(completed.stdout.encode("utf-8")) > _MAX_CONFIG_OUTPUT_BYTES:
        raise ComposeConfigResolutionError("compose_config_output_too_large")

    try:
        resolved = json.loads(completed.stdout)
    except (json.JSONDecodeError, UnicodeError, TypeError, ValueError) as exc:
        raise ComposeConfigResolutionError("compose_config_output_invalid") from exc
    if not isinstance(resolved, dict):
        raise ComposeConfigResolutionError("compose_config_output_invalid")

    try:
        validate_resolved_anvil_fork_compose(
            resolved,
            expected_runtime={
                "upstream_url": runtime_config["upstream_url"],
                "allowed_hosts": hosts,
                "bearer_token": runtime_config["bearer_token"],
                "foundry_image": runtime_config["foundry_image"],
                "fork_chain_id": fork_chain_id,
                "fork_block_number": fork_block_number,
            },
        )
    except ComposeTopologyValidationError as exc:
        raise ComposeConfigResolutionError(str(exc)) from exc

    return resolved
