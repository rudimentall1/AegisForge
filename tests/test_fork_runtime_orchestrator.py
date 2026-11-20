import copy
from pathlib import Path
from dataclasses import FrozenInstanceError

import pytest
import yaml

from agents.security_checker.fork_engine import build_fork_snapshot
from agents.security_checker.fork_execution_plan import build_fork_execution_plan
from agents.security_checker.fork_runtime_orchestrator import (
    ForkRuntimePreparationError,
    prepare_fork_runtime,
)


def _snapshot():
    return build_fork_snapshot(
        chain_id=42161,
        block_number=123456,
        block_hash="0x" + "a" * 64,
        contract_address="0x" + "b" * 40,
        runtime_bytecode="0x6001600055",
    )


COMPOSE_PATH = Path(__file__).resolve().parents[1] / "deploy" / "anvil-fork" / "compose.yaml"


def _resolved_compose(config, plan):
    document = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
    services = document["services"]
    allowed_hosts = ",".join(sorted(config["allowed_hosts"]))
    services["rpc-gateway"]["environment"].update(
        {
            "AEGISFORGE_RPC_GATEWAY_UPSTREAM_URL": config["upstream_url"],
            "AEGISFORGE_RPC_GATEWAY_ALLOWED_HOSTS": allowed_hosts,
            "AEGISFORGE_RPC_GATEWAY_TOKEN": config["bearer_token"],
        }
    )
    services["anvil-rpc-adapter"]["environment"][
        "AEGISFORGE_ANVIL_GATEWAY_TOKEN"
    ] = config["bearer_token"]
    services["anvil"]["image"] = config["foundry_image"]
    services["anvil"]["command"] = [
        "--host", "0.0.0.0",
        "--port", "8545",
        "--chain-id", str(plan["fork_chain_id"]),
        "--fork-url", "http://anvil-rpc-adapter:8546",
        "--fork-block-number", str(plan["block_number"]),
    ]
    return document


def _prepare(snapshot, plan, config, *, compose_source=None, resolved_compose=None):
    source = compose_source if compose_source is not None else COMPOSE_PATH.read_text(encoding="utf-8")
    resolved = resolved_compose if resolved_compose is not None else _resolved_compose(config, plan)
    return prepare_fork_runtime(
        snapshot,
        plan,
        config,
        compose_source=source,
        resolved_compose=resolved,
    )


def _config(**overrides):
    config = {
        "upstream_url": "https://arb-mainnet.example-rpc.com/v1/private-key",
        "allowed_hosts": ["arb-mainnet.example-rpc.com"],
        "bearer_token": "t" * 48,
        "foundry_image": "ghcr.io/foundry-rs/foundry@sha256:" + "a" * 64,
    }
    config.update(overrides)
    return config


def test_prepare_revalidates_snapshot_plan_and_returns_prepared_only_state():
    snapshot = _snapshot()
    plan = build_fork_execution_plan(snapshot, fork_chain_id=31338)

    prepared = _prepare(snapshot, plan, _config())

    assert prepared.state == "PREPARED"
    assert prepared.snapshot_sha256 == plan["snapshot_sha256"]
    assert prepared.fork_chain_id == 31338
    assert prepared.block_number == 123456
    assert prepared.compose_environment == (
        ("AEGISFORGE_ANVIL_CHAIN_ID", "31338"),
        ("AEGISFORGE_ANVIL_FORK_BLOCK_NUMBER", "123456"),
        ("AEGISFORGE_FOUNDRY_IMAGE", "ghcr.io/foundry-rs/foundry@sha256:" + "a" * 64),
    )
    assert prepared.required_secret_inputs == (
        "AEGISFORGE_RPC_GATEWAY_UPSTREAM_URL",
        "AEGISFORGE_RPC_GATEWAY_ALLOWED_HOSTS",
        "AEGISFORGE_RPC_GATEWAY_TOKEN",
    )
    assert prepared.runtime_started is False
    assert prepared.dynamic_verified is False
    assert prepared.confirmed is False
    assert prepared.compose_validation.state == "RESOLVED_STATIC_VALIDATED"
    assert prepared.compose_validation.runtime_started is False


def test_prepare_rejects_snapshot_plan_mismatch_before_preparation():
    snapshot = _snapshot()
    plan = build_fork_execution_plan(snapshot, fork_chain_id=31338)
    changed = copy.deepcopy(snapshot)
    changed["block_number"] += 1

    with pytest.raises(ForkRuntimePreparationError, match="snapshot_binding_mismatch"):
        _prepare(changed, plan, _config())


@pytest.mark.parametrize(
    "config",
    [
        _config(bearer_token=""),
        _config(bearer_token="short"),
        _config(bearer_token="x" * 32 + "\n"),
    ],
)
def test_prepare_rejects_missing_or_invalid_gateway_secret(config):
    snapshot = _snapshot()
    plan = build_fork_execution_plan(snapshot, fork_chain_id=31338)

    with pytest.raises(ForkRuntimePreparationError, match="gateway_token_invalid"):
        _prepare(snapshot, plan, config)


def test_prepare_rejects_provider_host_outside_exact_allowlist():
    snapshot = _snapshot()
    plan = build_fork_execution_plan(snapshot, fork_chain_id=31338)
    config = _config(upstream_url="https://evil.example/rpc")

    with pytest.raises(ForkRuntimePreparationError, match="upstream_url_not_allowlisted"):
        _prepare(snapshot, plan, config)


@pytest.mark.parametrize(
    "url",
    [
        "http://arb-mainnet.example-rpc.com/rpc",
        "https://user:pass@arb-mainnet.example-rpc.com/rpc",
        "https://arb-mainnet.example-rpc.com:8443/rpc",
        "https://arb-mainnet.example-rpc.com/rpc#fragment",
    ],
)
def test_prepare_rejects_unsafe_provider_url_shapes(url):
    snapshot = _snapshot()
    plan = build_fork_execution_plan(snapshot, fork_chain_id=31338)

    with pytest.raises(ForkRuntimePreparationError):
        _prepare(snapshot, plan, _config(upstream_url=url))


@pytest.mark.parametrize(
    "image",
    [
        "ghcr.io/foundry-rs/foundry:latest",
        "ghcr.io/foundry-rs/foundry:stable",
        "ghcr.io/foundry-rs/foundry@sha256:not-a-digest",
        "ghcr.io/foundry-rs/foundry@sha256:" + "A" * 64,
    ],
)
def test_prepare_rejects_non_immutable_or_malformed_foundry_image(image):
    snapshot = _snapshot()
    plan = build_fork_execution_plan(snapshot, fork_chain_id=31338)

    with pytest.raises(ForkRuntimePreparationError, match="foundry_image_not_digest_pinned"):
        _prepare(snapshot, plan, _config(foundry_image=image))


def test_secret_values_are_not_retained_or_rendered_in_prepared_result():
    snapshot = _snapshot()
    plan = build_fork_execution_plan(snapshot, fork_chain_id=31338)
    secret = "super-secret-gateway-token-" + "x" * 32
    upstream = "https://arb-mainnet.example-rpc.com/" + secret

    prepared = _prepare(
        snapshot,
        plan,
        _config(bearer_token=secret, upstream_url=upstream),
    )

    assert secret not in repr(prepared)
    assert secret not in str(prepared)
    assert secret not in repr(prepared.compose_environment)
    assert "AEGISFORGE_RPC_GATEWAY_TOKEN" not in dict(prepared.compose_environment)
    assert upstream not in repr(prepared)


def test_prepared_result_is_immutable_and_cannot_claim_execution():
    snapshot = _snapshot()
    plan = build_fork_execution_plan(snapshot, fork_chain_id=31338)
    prepared = _prepare(snapshot, plan, _config())

    with pytest.raises((FrozenInstanceError, AttributeError)):
        prepared.runtime_started = True
    assert prepared.state == "PREPARED"
    assert prepared.dynamic_verified is False
    assert prepared.confirmed is False


def test_prepare_rejects_unrecognized_configuration_fields():
    snapshot = _snapshot()
    plan = build_fork_execution_plan(snapshot, fork_chain_id=31338)
    config = _config(arbitrary_command="curl attacker.example")

    with pytest.raises(ForkRuntimePreparationError, match="runtime_configuration_fields_invalid"):
        _prepare(snapshot, plan, config)



def test_prepare_rejects_compose_topology_before_prepared_state():
    snapshot = _snapshot()
    plan = build_fork_execution_plan(snapshot, fork_chain_id=31338)
    source = COMPOSE_PATH.read_text(encoding="utf-8").replace(
        "    networks:\n      - fork-internal\n    read_only: true",
        "    networks:\n      - fork-internal\n      - rpc-egress\n    read_only: true",
        1,
    )

    with pytest.raises(ForkRuntimePreparationError, match="adapter_network_boundary_invalid"):
        _prepare(snapshot, plan, _config(), compose_source=source)



def test_prepare_rejects_resolved_compose_secret_or_runtime_mismatch():
    snapshot = _snapshot()
    plan = build_fork_execution_plan(snapshot, fork_chain_id=31338)
    config = _config()
    resolved = _resolved_compose(config, plan)
    resolved["services"]["anvil-rpc-adapter"]["environment"][
        "AEGISFORGE_ANVIL_GATEWAY_TOKEN"
    ] = "wrong-token"

    with pytest.raises(ForkRuntimePreparationError, match="resolved_gateway_secret_mismatch"):
        _prepare(snapshot, plan, config, resolved_compose=resolved)
