import json
import subprocess
from pathlib import Path

import pytest
import yaml

from agents.security_checker.fork_compose_resolver import (
    ComposeConfigResolutionError,
    resolve_anvil_fork_compose,
)


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy" / "anvil-fork" / "compose.yaml"
IMAGE = "ghcr.io/foundry-rs/foundry@sha256:" + "a" * 64


def _runtime():
    return {
        "upstream_url": "https://rpc.example.test/v1/key",
        "allowed_hosts": ["rpc.example.test"],
        "bearer_token": "s" * 48,
        "foundry_image": IMAGE,
    }


def _compose_json():
    document = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    services = document["services"]
    config = _runtime()
    services["rpc-gateway"]["environment"].update(
        {
            "AEGISFORGE_RPC_GATEWAY_UPSTREAM_URL": config["upstream_url"],
            "AEGISFORGE_RPC_GATEWAY_ALLOWED_HOSTS": "rpc.example.test",
            "AEGISFORGE_RPC_GATEWAY_TOKEN": config["bearer_token"],
        }
    )
    services["anvil-rpc-adapter"]["environment"][
        "AEGISFORGE_ANVIL_GATEWAY_TOKEN"
    ] = config["bearer_token"]
    services["anvil"]["image"] = IMAGE
    services["anvil"]["command"] = [
        "--host", "0.0.0.0",
        "--port", "8545",
        "--chain-id", "31338",
        "--fork-url", "http://anvil-rpc-adapter:8546",
        "--fork-block-number", "123456",
    ]
    for service in services.values():
        networks = service.get("networks", [])
        if isinstance(networks, list):
            service["networks"] = {name: None for name in networks}
    document["networks"]["fork-internal"]["name"] = "aegisforge-anvil-fork_fork-internal"
    document["networks"]["rpc-egress"]["name"] = "aegisforge-anvil-fork_rpc-egress"
    return document


def test_resolver_runs_only_fixed_compose_config_command_and_validates_json(monkeypatch):
    expected = _compose_json()
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, json.dumps(expected), "secret stderr")

    monkeypatch.setattr(
        "agents.security_checker.fork_compose_resolver.subprocess.run",
        fake_run,
    )

    resolved = resolve_anvil_fork_compose(
        runtime_config=_runtime(),
        fork_chain_id=31338,
        fork_block_number=123456,
    )

    assert resolved == expected
    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args[-3:] == ["config", "--format", "json"]
    assert args[0].endswith("/docker")
    assert "--env-file" in args and "/dev/null" in args
    assert kwargs["shell"] is False
    assert kwargs["stdin"] == subprocess.DEVNULL
    assert kwargs["stderr"] == subprocess.DEVNULL
    assert kwargs["timeout"] <= 20
    assert kwargs["env"]["AEGISFORGE_RPC_GATEWAY_TOKEN"] == "s" * 48
    assert set(kwargs["env"]).issubset(
        {
            "PATH",
            "HOME",
            "AEGISFORGE_RPC_GATEWAY_UPSTREAM_URL",
            "AEGISFORGE_RPC_GATEWAY_ALLOWED_HOSTS",
            "AEGISFORGE_RPC_GATEWAY_TOKEN",
            "AEGISFORGE_ANVIL_CHAIN_ID",
            "AEGISFORGE_ANVIL_FORK_BLOCK_NUMBER",
            "AEGISFORGE_FOUNDRY_IMAGE",
        }
    )


def test_resolver_does_not_expose_compose_stderr_or_secret_in_errors(monkeypatch):
    secret = "s" * 48

    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args, 1, "", "provider token " + secret)

    monkeypatch.setattr(
        "agents.security_checker.fork_compose_resolver.subprocess.run",
        fake_run,
    )

    with pytest.raises(ComposeConfigResolutionError) as error:
        resolve_anvil_fork_compose(
            runtime_config=_runtime(),
            fork_chain_id=31338,
            fork_block_number=123456,
        )

    assert secret not in str(error.value)
    assert "provider token" not in str(error.value)


def test_resolver_rejects_oversized_compose_output(monkeypatch):
    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args, 0, " " * (2 * 1024 * 1024), "")

    monkeypatch.setattr(
        "agents.security_checker.fork_compose_resolver.subprocess.run",
        fake_run,
    )

    with pytest.raises(ComposeConfigResolutionError, match="compose_config_output_too_large"):
        resolve_anvil_fork_compose(
            runtime_config=_runtime(),
            fork_chain_id=31338,
            fork_block_number=123456,
        )


def test_resolver_rejects_invalid_json_without_echoing_output(monkeypatch):
    secret = "s" * 48

    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args, 0, secret + "{not-json", "")

    monkeypatch.setattr(
        "agents.security_checker.fork_compose_resolver.subprocess.run",
        fake_run,
    )

    with pytest.raises(ComposeConfigResolutionError, match="compose_config_output_invalid") as error:
        resolve_anvil_fork_compose(
            runtime_config=_runtime(),
            fork_chain_id=31338,
            fork_block_number=123456,
        )

    assert secret not in str(error.value)


def test_resolver_rejects_command_timeout_without_leaking_output(monkeypatch):
    def fake_run(args, **kwargs):
        raise subprocess.TimeoutExpired(args, kwargs["timeout"], output="sensitive")

    monkeypatch.setattr(
        "agents.security_checker.fork_compose_resolver.subprocess.run",
        fake_run,
    )

    with pytest.raises(ComposeConfigResolutionError, match="compose_config_timeout"):
        resolve_anvil_fork_compose(
            runtime_config=_runtime(),
            fork_chain_id=31338,
            fork_block_number=123456,
        )


def test_resolver_rejects_unavailable_docker_cli(monkeypatch):
    monkeypatch.setattr(
        "agents.security_checker.fork_compose_resolver.shutil.which",
        lambda command: None,
    )

    with pytest.raises(ComposeConfigResolutionError, match="docker_cli_unavailable"):
        resolve_anvil_fork_compose(
            runtime_config=_runtime(),
            fork_chain_id=31338,
            fork_block_number=123456,
        )
