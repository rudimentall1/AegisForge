import copy
from dataclasses import FrozenInstanceError

import pytest

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

    prepared = prepare_fork_runtime(snapshot, plan, _config())

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


def test_prepare_rejects_snapshot_plan_mismatch_before_preparation():
    snapshot = _snapshot()
    plan = build_fork_execution_plan(snapshot, fork_chain_id=31338)
    changed = copy.deepcopy(snapshot)
    changed["block_number"] += 1

    with pytest.raises(ForkRuntimePreparationError, match="snapshot_invalid"):
        prepare_fork_runtime(changed, plan, _config())


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
        prepare_fork_runtime(snapshot, plan, config)


def test_prepare_rejects_provider_host_outside_exact_allowlist():
    snapshot = _snapshot()
    plan = build_fork_execution_plan(snapshot, fork_chain_id=31338)
    config = _config(upstream_url="https://evil.example/rpc")

    with pytest.raises(ForkRuntimePreparationError, match="upstream_url_not_allowlisted"):
        prepare_fork_runtime(snapshot, plan, config)


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
        prepare_fork_runtime(snapshot, plan, _config(upstream_url=url))


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
        prepare_fork_runtime(snapshot, plan, _config(foundry_image=image))


def test_secret_values_are_not_retained_or_rendered_in_prepared_result():
    snapshot = _snapshot()
    plan = build_fork_execution_plan(snapshot, fork_chain_id=31338)
    secret = "super-secret-gateway-token-" + "x" * 32
    upstream = "https://arb-mainnet.example-rpc.com/" + secret

    prepared = prepare_fork_runtime(
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
    prepared = prepare_fork_runtime(snapshot, plan, _config())

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
        prepare_fork_runtime(snapshot, plan, config)
