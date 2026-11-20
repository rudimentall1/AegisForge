from pathlib import Path

import pytest
import yaml

from agents.security_checker.fork_compose_validator import (
    ComposeTopologyValidationError,
    validate_anvil_fork_compose,
)


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy" / "anvil-fork" / "compose.yaml"


def _source():
    return COMPOSE.read_text(encoding="utf-8")


FOUNDRY_IMAGE = "ghcr.io/foundry-rs/foundry@sha256:" + "a" * 64


def _validate(source):
    return validate_anvil_fork_compose(source, foundry_image=FOUNDRY_IMAGE)


def _mutated_source(mutator):
    document = yaml.safe_load(_source())
    mutator(document)
    return yaml.safe_dump(document, sort_keys=False)


def test_validator_accepts_repository_topology_and_returns_static_only_report():
    report = _validate(_source())

    assert report.state == "STATIC_VALIDATED"
    assert report.services == ("rpc-gateway", "anvil-rpc-adapter", "anvil")
    assert report.egress_service == "rpc-gateway"
    assert report.runtime_started is False
    assert report.dynamic_verified is False
    assert report.confirmed is False
    assert "single_egress_gateway" in report.checked_invariants
    assert "no_published_ports" in report.checked_invariants


def test_validator_rejects_adapter_egress_network_attachment():
    source = _mutated_source(
        lambda doc: doc["services"]["anvil-rpc-adapter"]["networks"].append("rpc-egress")
    )

    with pytest.raises(ComposeTopologyValidationError, match="adapter_network_boundary_invalid"):
        _validate(source)


def test_validator_rejects_anvil_egress_network_attachment():
    source = _mutated_source(
        lambda doc: doc["services"]["anvil"]["networks"].append("rpc-egress")
    )

    with pytest.raises(ComposeTopologyValidationError, match="anvil_network_boundary_invalid"):
        _validate(source)


def test_validator_rejects_published_host_ports():
    source = _mutated_source(
        lambda doc: doc["services"]["anvil"].update({"ports": ["8545:8545"]})
    )

    with pytest.raises(ComposeTopologyValidationError, match="published_ports_forbidden"):
        _validate(source)


def test_validator_rejects_non_internal_fork_network():
    source = _mutated_source(
        lambda doc: doc["networks"]["fork-internal"].update({"internal": False})
    )

    with pytest.raises(ComposeTopologyValidationError, match="fork_internal_network_invalid"):
        _validate(source)


def test_validator_rejects_missing_explicit_fork_chain_id():
    source = _mutated_source(
        lambda doc: doc["services"]["anvil"]["command"].__setitem__(
            doc["services"]["anvil"]["command"].index(
                "${AEGISFORGE_ANVIL_CHAIN_ID:?Set the explicit fork chain ID from the execution plan}"
            ),
            "31337",
        )
    )

    with pytest.raises(ComposeTopologyValidationError, match="anvil_fork_identity_invalid"):
        _validate(source)


def test_validator_rejects_missing_pinned_fork_block():
    source = _mutated_source(
        lambda doc: doc["services"]["anvil"]["command"].__setitem__(
            doc["services"]["anvil"]["command"].index(
                "${AEGISFORGE_ANVIL_FORK_BLOCK_NUMBER:?Set an exact fork block number}"
            ),
            "latest",
        )
    )

    with pytest.raises(ComposeTopologyValidationError, match="anvil_fork_identity_invalid"):
        _validate(source)


def test_validator_rejects_anvil_gateway_credentials():
    source = _mutated_source(
        lambda doc: doc["services"]["anvil"].update(
            {"environment": {"AEGISFORGE_RPC_GATEWAY_TOKEN": "should-never-be-here"}}
        )
    )

    with pytest.raises(ComposeTopologyValidationError, match="anvil_environment_invalid"):
        _validate(source)


def test_validator_rejects_gateway_without_egress_route_priority():
    source = _mutated_source(
        lambda doc: doc["services"]["rpc-gateway"]["networks"]["rpc-egress"].pop(
            "gw_priority"
        )
    )

    with pytest.raises(ComposeTopologyValidationError, match="gateway_egress_route_invalid"):
        _validate(source)


def test_validator_rejects_non_digest_foundry_image_reference():
    source = _mutated_source(
        lambda doc: doc["services"]["anvil"].update({"image": "foundry:latest"})
    )

    with pytest.raises(ComposeTopologyValidationError, match="foundry_image_reference_invalid"):
        _validate(source)


def test_validator_rejects_unexpected_compose_services():
    source = _mutated_source(
        lambda doc: doc["services"].update({"debug-shell": {"image": "busybox"}})
    )

    with pytest.raises(ComposeTopologyValidationError, match="compose_services_invalid"):
        _validate(source)


def test_validator_rejects_duplicate_yaml_keys_without_silent_overwrite():
    source = _source().replace(
        "  anvil:\n",
        "  anvil:\n    image: busybox\n",
        1,
    )

    with pytest.raises(ComposeTopologyValidationError, match="compose_yaml_invalid"):
        _validate(source)



def test_validator_rejects_unpinned_resolved_foundry_image():
    with pytest.raises(ComposeTopologyValidationError, match="foundry_image_not_digest_pinned"):
        validate_anvil_fork_compose(_source(), foundry_image="foundry:latest")
