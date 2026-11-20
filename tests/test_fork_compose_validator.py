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



def test_validator_rejects_relaxed_anvil_resource_limits():
    source = _mutated_source(
        lambda doc: doc["services"]["anvil"].update({"pids_limit": 4096})
    )

    with pytest.raises(ComposeTopologyValidationError, match="anvil_pids_limit_invalid"):
        _validate(source)



def _resolved_compose():
    document = yaml.safe_load(_source())
    services = document["services"]
    services["rpc-gateway"]["environment"].update(
        {
            "AEGISFORGE_RPC_GATEWAY_UPSTREAM_URL": "https://arb-mainnet.example-rpc.com/v1/key",
            "AEGISFORGE_RPC_GATEWAY_ALLOWED_HOSTS": "arb-mainnet.example-rpc.com",
            "AEGISFORGE_RPC_GATEWAY_TOKEN": "r" * 48,
        }
    )
    services["anvil-rpc-adapter"]["environment"][
        "AEGISFORGE_ANVIL_GATEWAY_TOKEN"
    ] = "r" * 48
    services["anvil"]["image"] = FOUNDRY_IMAGE
    services["anvil"]["command"] = [
        "--host", "0.0.0.0",
        "--port", "8545",
        "--chain-id", "31338",
        "--fork-url", "http://anvil-rpc-adapter:8546",
        "--fork-block-number", "123456",
    ]
    for service in services.values():
        if isinstance(service.get("networks"), list):
            service["networks"] = {name: None for name in service["networks"]}
    document["networks"]["fork-internal"]["name"] = "aegisforge-anvil-fork_fork-internal"
    document["networks"]["rpc-egress"]["name"] = "aegisforge-anvil-fork_rpc-egress"
    return document


def _resolved_expectations(**overrides):
    expected = {
        "upstream_url": "https://arb-mainnet.example-rpc.com/v1/key",
        "allowed_hosts": ("arb-mainnet.example-rpc.com",),
        "bearer_token": "r" * 48,
        "foundry_image": FOUNDRY_IMAGE,
        "fork_chain_id": 31338,
        "fork_block_number": 123456,
    }
    expected.update(overrides)
    return expected


def test_resolved_compose_validator_accepts_effective_interpolated_configuration():
    from agents.security_checker.fork_compose_validator import (
        validate_resolved_anvil_fork_compose,
    )

    report = validate_resolved_anvil_fork_compose(
        _resolved_compose(),
        expected_runtime=_resolved_expectations(),
    )

    assert report.state == "RESOLVED_STATIC_VALIDATED"
    assert report.runtime_started is False
    assert report.dynamic_verified is False
    assert report.confirmed is False
    assert "resolved_secret_consistency" in report.checked_invariants


def test_resolved_compose_rejects_gateway_secret_mismatch():
    from agents.security_checker.fork_compose_validator import (
        validate_resolved_anvil_fork_compose,
    )

    document = _resolved_compose()
    document["services"]["anvil-rpc-adapter"]["environment"][
        "AEGISFORGE_ANVIL_GATEWAY_TOKEN"
    ] = "different-secret"

    with pytest.raises(ComposeTopologyValidationError, match="resolved_gateway_secret_mismatch"):
        validate_resolved_anvil_fork_compose(
            document,
            expected_runtime=_resolved_expectations(),
        )


def test_resolved_compose_rejects_provider_url_not_matching_runtime_configuration():
    from agents.security_checker.fork_compose_validator import (
        validate_resolved_anvil_fork_compose,
    )

    document = _resolved_compose()
    document["services"]["rpc-gateway"]["environment"][
        "AEGISFORGE_RPC_GATEWAY_UPSTREAM_URL"
    ] = "https://attacker.example/rpc"

    with pytest.raises(ComposeTopologyValidationError, match="resolved_gateway_environment_invalid"):
        validate_resolved_anvil_fork_compose(
            document,
            expected_runtime=_resolved_expectations(),
        )


def test_resolved_compose_rejects_published_ports_and_extra_networks():
    from agents.security_checker.fork_compose_validator import (
        validate_resolved_anvil_fork_compose,
    )

    document = _resolved_compose()
    document["services"]["anvil"]["ports"] = [{"target": 8545, "published": "8545"}]

    with pytest.raises(ComposeTopologyValidationError, match="resolved_published_ports_forbidden"):
        validate_resolved_anvil_fork_compose(
            document,
            expected_runtime=_resolved_expectations(),
        )


def test_resolved_compose_rejects_changed_chain_or_block_anchor():
    from agents.security_checker.fork_compose_validator import (
        validate_resolved_anvil_fork_compose,
    )

    document = _resolved_compose()
    document["services"]["anvil"]["command"][-1] = "latest"

    with pytest.raises(ComposeTopologyValidationError, match="resolved_anvil_fork_identity_invalid"):
        validate_resolved_anvil_fork_compose(
            document,
            expected_runtime=_resolved_expectations(),
        )


def test_resolved_compose_rejects_unexpected_privileged_service_options():
    from agents.security_checker.fork_compose_validator import (
        validate_resolved_anvil_fork_compose,
    )

    document = _resolved_compose()
    document["services"]["anvil"]["privileged"] = True

    with pytest.raises(ComposeTopologyValidationError, match="resolved_privileged_mode_forbidden"):
        validate_resolved_anvil_fork_compose(
            document,
            expected_runtime=_resolved_expectations(),
        )



def test_resolved_compose_rejects_expected_provider_outside_allowlist():
    from agents.security_checker.fork_compose_validator import (
        validate_resolved_anvil_fork_compose,
    )

    with pytest.raises(ComposeTopologyValidationError, match="resolved_runtime_expectations_invalid"):
        validate_resolved_anvil_fork_compose(
            _resolved_compose(),
            expected_runtime=_resolved_expectations(
                upstream_url="https://attacker.example/rpc",
            ),
        )


def test_resolved_compose_report_never_retains_gateway_secret_or_provider_url():
    from agents.security_checker.fork_compose_validator import (
        validate_resolved_anvil_fork_compose,
    )

    expected = _resolved_expectations()
    report = validate_resolved_anvil_fork_compose(
        _resolved_compose(),
        expected_runtime=expected,
    )

    assert expected["bearer_token"] not in repr(report)
    assert expected["upstream_url"] not in repr(report)


def test_resolved_compose_rejects_anvil_attached_to_egress_network():
    from agents.security_checker.fork_compose_validator import (
        validate_resolved_anvil_fork_compose,
    )

    document = _resolved_compose()
    document["services"]["anvil"]["networks"]["rpc-egress"] = {}

    with pytest.raises(ComposeTopologyValidationError, match="resolved_anvil_network_boundary_invalid"):
        validate_resolved_anvil_fork_compose(
            document,
            expected_runtime=_resolved_expectations(),
        )



def test_resolved_compose_accepts_canonical_project_network_names():
    from agents.security_checker.fork_compose_validator import (
        validate_resolved_anvil_fork_compose,
    )

    document = _resolved_compose()
    document["services"]["anvil-rpc-adapter"]["networks"] = {"fork-internal": None}
    document["services"]["anvil"]["networks"] = {"fork-internal": None}
    document["networks"]["fork-internal"]["name"] = "aegisforge-anvil-fork_fork-internal"
    document["networks"]["rpc-egress"]["name"] = "aegisforge-anvil-fork_rpc-egress"

    report = validate_resolved_anvil_fork_compose(
        document,
        expected_runtime=_resolved_expectations(),
    )

    assert report.state == "RESOLVED_STATIC_VALIDATED"


def test_resolved_compose_rejects_unrecognized_service_configuration_fields():
    from agents.security_checker.fork_compose_validator import (
        validate_resolved_anvil_fork_compose,
    )

    document = _resolved_compose()
    document["services"]["anvil"]["restart"] = "always"

    with pytest.raises(ComposeTopologyValidationError, match="resolved_compose_service_fields_invalid"):
        validate_resolved_anvil_fork_compose(
            document,
            expected_runtime=_resolved_expectations(),
        )


def test_resolved_compose_rejects_unexpected_project_network_name():
    from agents.security_checker.fork_compose_validator import (
        validate_resolved_anvil_fork_compose,
    )

    document = _resolved_compose()
    document["networks"]["rpc-egress"]["name"] = "attacker-controlled-network"

    with pytest.raises(ComposeTopologyValidationError, match="resolved_rpc_egress_network_invalid"):
        validate_resolved_anvil_fork_compose(
            document,
            expected_runtime=_resolved_expectations(),
        )
