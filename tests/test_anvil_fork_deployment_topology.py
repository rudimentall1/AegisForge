"""Static guardrails for the Anvil fork deployment topology."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy" / "anvil-fork" / "compose.yaml"
DOCKERFILE = ROOT / "deploy" / "anvil-fork" / "Dockerfile.rpc-sidecar"
GUIDE = ROOT / "docs" / "ANVIL-FORK-DEPLOYMENT.md"
FIREWALL = ROOT / "deploy" / "anvil-fork" / "install_egress_firewall.py"


def _service_block(source: str, name: str) -> str:
    match = re.search(
        rf"^  {re.escape(name)}:\n(?P<body>(?:^    .*\n|^\n)*)",
        source,
        re.MULTILINE,
    )
    assert match is not None, f"missing compose service: {name}"
    return match.group("body")


def test_fork_topology_has_gateway_adapter_and_anvil():
    source = COMPOSE.read_text(encoding="utf-8")
    for service in ("rpc-gateway", "anvil-rpc-adapter", "anvil"):
        assert re.search(rf"^  {service}:$", source, re.MULTILINE)


def test_only_gateway_joins_the_egress_network_and_no_ports_are_published():
    source = COMPOSE.read_text(encoding="utf-8")
    gateway = _service_block(source, "rpc-gateway")
    adapter = _service_block(source, "anvil-rpc-adapter")
    anvil = _service_block(source, "anvil")

    assert "rpc-egress" in gateway
    assert "gw_priority: 1" in gateway
    assert "rpc-egress" not in adapter
    assert "rpc-egress" not in anvil
    assert "ports:" not in source


def test_anvil_and_adapter_share_only_the_internal_fork_network():
    source = COMPOSE.read_text(encoding="utf-8")
    adapter = _service_block(source, "anvil-rpc-adapter")
    anvil = _service_block(source, "anvil")

    assert "fork-internal" in adapter
    assert "fork-internal" in anvil
    assert "internal: true" in source
    assert source.count("enable_ipv6: false") == 2


def test_images_are_required_as_immutable_user_supplied_references():
    source = COMPOSE.read_text(encoding="utf-8")
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")

    assert "${AEGISFORGE_FOUNDRY_IMAGE:?}" in source
    assert "aegisforge-rpc-sidecar:local" in source
    assert re.search(r"(?m)^ARG PYTHON_IMAGE$", dockerfile)
    assert re.search(r"(?m)^FROM \${PYTHON_IMAGE}$", dockerfile)
    assert "python:latest" not in dockerfile.lower()
    env_example = (ROOT / "deploy" / "anvil-fork" / ".env.example").read_text(encoding="utf-8")
    assert "AEGISFORGE_PYTHON_IMAGE=" in env_example


def test_fork_block_is_explicit_and_credentials_are_not_anvil_arguments():
    source = COMPOSE.read_text(encoding="utf-8")
    anvil = _service_block(source, "anvil")

    assert "${AEGISFORGE_ANVIL_FORK_BLOCK_NUMBER:?}" in anvil
    assert "${AEGISFORGE_ANVIL_CHAIN_ID:?}" in anvil
    assert "--fork-header" not in anvil
    assert "AEGISFORGE_ANVIL_GATEWAY_TOKEN" not in anvil


def test_deployment_guide_does_not_claim_compose_enforces_provider_egress():
    guide = GUIDE.read_text(encoding="utf-8").lower()
    assert "host firewall" in guide
    assert "does not enforce" in guide
    assert "approved rpc" in guide


def test_egress_bridge_is_dedicated_and_firewall_allows_only_provider_https():
    compose = COMPOSE.read_text(encoding="utf-8")
    firewall = FIREWALL.read_text(encoding="utf-8")
    egress = compose.split("  rpc-egress:", 1)[1]

    assert 'com.docker.network.bridge.enable_icc: "false"' in egress
    assert "br-aegisforge" in egress
    assert 'iifname "br-aegisforge" ip saddr {gateway} ip daddr @approved_rpc_v4 tcp dport 443 ct state new counter accept' in firewall
    assert 'oifname "br-aegisforge" ip saddr @approved_rpc_v4 ip daddr {gateway} ct state established,related counter accept' in firewall
    assert 'iifname "br-aegisforge" counter drop' in firewall
    assert 'iifname "br-aegisforge" ip saddr {gateway} counter drop' not in firewall
    assert 'oifname "br-aegisforge" ip daddr {gateway} counter drop' in firewall
    assert "priority -10" in firewall
