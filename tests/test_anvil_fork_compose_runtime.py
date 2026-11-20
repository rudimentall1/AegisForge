"""Disposable Docker Compose runtime checks for the Anvil fork network boundary.

Runs on an ephemeral CI Docker host. The dedicated nftables table is applied
only when an explicit GitHub-hosted-runner flag is set, and is always removed.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from uuid import uuid4

from pathlib import Path

from agents.security_checker.packet_path_evidence import validate_packet_path_receipt

import pytest


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy" / "anvil-fork" / "compose.yaml"
OVERRIDE = ROOT / "tests" / "fixtures" / "anvil-fork-compose-runtime.override.yaml"
DOCKERFILE = ROOT / "deploy" / "anvil-fork" / "Dockerfile.rpc-sidecar"
FIREWALL_SCRIPT = ROOT / "deploy" / "anvil-fork" / "install_egress_firewall.py"
FIREWALL_TABLE = "aegisforge_gateway_egress"


def test_docker_tcp_probe_script_is_valid_python():
    compile(_docker_tcp_probe_script(), "<docker-tcp-probe>", "exec")


def _run(command: list[str], *, timeout: int = 90) -> str:
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if result.returncode:
        raise AssertionError(
            f"command_failed:{command!r}:\nstdout={result.stdout}\nstderr={result.stderr}"
        )
    return result.stdout.strip()


def _nft_counter(rule_fragment: str, verdict: str) -> int:
    output = _run(
        ["sudo", "-n", "nft", "list", "chain", "inet", FIREWALL_TABLE, "forward_guard"]
    )
    for line in output.splitlines():
        if rule_fragment in line and line.rstrip().endswith(verdict):
            match = re.search(r"counter packets (\d+)", line)
            if match:
                return int(match.group(1))
    raise AssertionError(f"firewall_rule_counter_missing:{rule_fragment}")



def _nft_ruleset_sha256() -> str:
    raw = _run(["sudo", "-n", "nft", "-j", "list", "table", "inet", FIREWALL_TABLE])
    document = json.loads(raw)

    def without_counters(value):
        if isinstance(value, list):
            return [without_counters(item) for item in value]
        if isinstance(value, dict):
            return {
                key: without_counters(item)
                for key, item in value.items()
                if key != "counter"
            }
        return value

    canonical = json.dumps(
        without_counters(document),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _docker_tcp_probe_script() -> str:
    """Return executable Python source for a TCP probe inside a test container."""
    return (
        "import socket, sys\n"
        "sock = socket.socket()\n"
        "sock.settimeout(1)\n"
        "try:\n"
        "    sock.connect((sys.argv[1], int(sys.argv[2])))\n"
        "    print('CONNECTED')\n"
        "except OSError as exc:\n"
        "    print('BLOCKED:' + type(exc).__name__)\n"
        "finally:\n"
        "    sock.close()\n"
    )


def _docker_tcp_connects(container_id: str, destination: str, port: int) -> bool:
    probe = _docker_tcp_probe_script()
    result = subprocess.run(
        [
            "docker", "exec", container_id, "python", "-c",
            probe, destination, str(port),
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"tcp_probe_execution_failed:{result.stderr}")
    outcome = result.stdout.strip()
    if outcome == "CONNECTED":
        return True
    if outcome.startswith("BLOCKED:"):
        return False
    raise AssertionError(f"tcp_probe_outcome_unrecognized:{outcome!r}")


def _docker_exec_output(container_id: str, command: list[str]) -> str:
    result = subprocess.run(
        ["docker", "exec", container_id, *command],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def _docker_exec_command(
    container_id: str,
    command: list[str],
    *,
    expect_success: bool,
) -> None:
    result = subprocess.run(
        ["docker", "exec", container_id, *command],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    if expect_success:
        assert result.returncode == 0, result.stderr
    else:
        assert result.returncode != 0, (
            "container unexpectedly reached an external IPv4 endpoint"
        )


def _docker_exec(
    container_id: str,
    code: str,
    *,
    expect_success: bool,
    args: tuple[str, ...] = (),
) -> None:
    _docker_exec_command(
        container_id,
        ["python", "-c", code, *args],
        expect_success=expect_success,
    )


@pytest.mark.skipif(
    shutil.which("docker") is None or shutil.which("ip") is None,
    reason="requires Docker Engine, Docker Compose v2 and iproute2 on an ephemeral CI host",
)
def test_real_compose_network_membership_and_internal_service_egress():
    python_image = os.environ.get("AEGISFORGE_PYTHON_IMAGE", "")
    assert "@sha256:" in python_image, "CI must provide a digest-pinned Python base image"

    firewall_runtime = os.environ.get("AEGISFORGE_DOCKER_FIREWALL_RUNTIME") == "1"
    if firewall_runtime:
        assert os.environ.get("GITHUB_ACTIONS") == "true"
        assert os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"

    project = f"aegisforge-compose-runtime-{os.getpid()}"
    image_tag = "aegisforge-rpc-sidecar:local"
    firewall_applied = False
    token = "aegisforge-compose-runtime-test-token-0123456789"
    with tempfile.TemporaryDirectory(prefix="aegisforge-compose-runtime-") as temporary:
        env_file = Path(temporary) / "compose.env"
        env_file.write_text(
            "\n".join(
                (
                    f"AEGISFORGE_PYTHON_IMAGE={python_image}",
                    "AEGISFORGE_FOUNDRY_IMAGE=ghcr.io/foundry-rs/foundry@sha256:" + "a" * 64,
                    "AEGISFORGE_RPC_GATEWAY_UPSTREAM_URL=https://rpc-provider.example/v1/test",
                    "AEGISFORGE_RPC_GATEWAY_ALLOWED_HOSTS=rpc-provider.example",
                    f"AEGISFORGE_RPC_GATEWAY_TOKEN={token}",
                    "AEGISFORGE_ANVIL_FORK_BLOCK_NUMBER=1",
                    "AEGISFORGE_ANVIL_CHAIN_ID=31337",
                    "",
                )
            ),
            encoding="utf-8",
        )
        compose = [
            "docker", "compose", "--project-name", project,
            "--env-file", str(env_file),
            "-f", str(COMPOSE),
            "-f", str(OVERRIDE),
        ]

        try:
            _run(
                [
                    "docker", "build", "--build-arg", f"PYTHON_IMAGE={python_image}",
                    "-t", "aegisforge-rpc-sidecar:local",
                    "-f", str(DOCKERFILE), ".",
                ],
                timeout=180,
            )
            # Create networks and containers first, but do not start services yet.
            # The host egress policy must be installed before the dual-homed Gateway
            # can emit any packets onto br-aegisforge.
            _run(compose + ["create"], timeout=120)
            if firewall_runtime:
                _run(
                    [
                        "sudo", "-n", sys.executable, str(FIREWALL_SCRIPT),
                        "--apply", "--provider-cidr", "8.8.8.8/32",
                    ]
                )
                firewall_applied = True
            _run(compose + ["up", "--detach", "--wait", "--wait-timeout", "60"], timeout=120)

            service_ids = {
                service: _run(compose + ["ps", "--quiet", service])
                for service in ("rpc-gateway", "anvil-rpc-adapter", "anvil")
            }
            assert all(service_ids.values()), f"Compose services did not start: {service_ids}"

            inspected = {
                service: json.loads(_run(["docker", "inspect", container_id]))[0]
                for service, container_id in service_ids.items()
            }
            gateway_networks = inspected["rpc-gateway"]["NetworkSettings"]["Networks"]
            adapter_networks = inspected["anvil-rpc-adapter"]["NetworkSettings"]["Networks"]
            anvil_networks = inspected["anvil"]["NetworkSettings"]["Networks"]

            assert set(gateway_networks) == {f"{project}_fork-internal", f"{project}_rpc-egress"}
            assert set(adapter_networks) == {f"{project}_fork-internal"}
            assert set(anvil_networks) == {f"{project}_fork-internal"}

            internal = json.loads(
                _run(["docker", "network", "inspect", f"{project}_fork-internal"])
            )[0]
            egress = json.loads(
                _run(["docker", "network", "inspect", f"{project}_rpc-egress"])
            )[0]
            assert internal["Internal"] is True
            assert internal["EnableIPv6"] is False
            assert egress["Internal"] is False
            assert egress["EnableIPv6"] is False
            assert egress["Options"]["com.docker.network.bridge.name"] == "br-aegisforge"
            egress_gateway = egress["IPAM"]["Config"][0]["Gateway"]
            assert gateway_networks[f"{project}_rpc-egress"]["IPAddress"] == "172.31.240.2"

            # The dual-homed Gateway must select rpc-egress as its default route.
            _docker_exec(
                service_ids["rpc-gateway"],
                "import socket,struct,sys; "
                "rows=open('/proc/net/route',encoding='ascii').read().splitlines()[1:]; "
                f"assert any((r:=line.split())[1]=='00000000' and "
                f"socket.inet_ntoa(struct.pack('<I',int(r[2],16)))=='{egress_gateway}' "
                "for line in rows)",
                expect_success=True,
            )
            egress_services = set()
            for container_id in egress["Containers"]:
                labels = json.loads(_run(["docker", "inspect", container_id]))[0]["Config"]["Labels"]
                egress_services.add(labels["com.docker.compose.service"])
            assert egress_services == {"rpc-gateway"}

            _run(["ip", "-o", "link", "show", "br-aegisforge"])

            # The test override deliberately replaces Anvil with the same
            # digest-pinned Python sidecar image, so both internal-only services
            # can perform namespace-local TCP probes without assuming tools in
            # the production Foundry image.
            adapter_gateway_internal_connected = _docker_tcp_connects(
                service_ids["anvil-rpc-adapter"], "rpc-gateway", 8545
            )
            anvil_adapter_internal_connected = _docker_tcp_connects(
                service_ids["anvil"], "anvil-rpc-adapter", 8546
            )
            assert adapter_gateway_internal_connected
            assert anvil_adapter_internal_connected

            # Both services must have no default route and must fail a real
            # external TCP connection attempt from their own network namespace.
            default_route_absent = {}
            for service in ("anvil-rpc-adapter", "anvil"):
                route_result = subprocess.run(
                    [
                        "docker", "exec", service_ids[service], "python", "-c",
                        "rows=open('/proc/net/route',encoding='ascii').read().splitlines()[1:]; "
                        "print('present' if any(line.split()[1]=='00000000' for line in rows) else 'absent')",
                    ],
                    cwd=ROOT,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                    check=False,
                )
                assert route_result.returncode == 0, route_result.stderr
                default_route_absent[service] = route_result.stdout.strip() == "absent"
                assert default_route_absent[service], (
                    f"{service} unexpectedly has a default route: {route_result.stderr}"
                )
                external_connected = _docker_tcp_connects(
                    service_ids[service], "8.8.8.8", 443
                )
                assert not external_connected, (
                    f"{service} unexpectedly established external TCP"
                )

            # Isolation is asserted from Docker's live network state, not from a
            # failed connection to an arbitrary public IP (which could be down).
            # Both services have exactly one attachment, to a Docker Internal network.
            assert internal["Internal"] is True
            assert set(adapter_networks) == {f"{project}_fork-internal"}
            assert set(anvil_networks) == {f"{project}_fork-internal"}

            if firewall_runtime:
                allowed_rule = (
                    'iifname "br-aegisforge" ip saddr 172.31.240.2 '
                    "ip daddr @approved_rpc_v4 tcp dport 443 ct state new"
                )
                denied_rule = 'iifname "br-aegisforge"'

                ruleset_sha256 = _nft_ruleset_sha256()
                allowed_before = _nft_counter(allowed_rule, "accept")
                approved_connected = _docker_tcp_connects(
                    service_ids["rpc-gateway"], "8.8.8.8", 443
                )
                allowed_after = _nft_counter(allowed_rule, "accept")
                assert allowed_after > allowed_before, (
                    "approved Gateway egress did not match the nftables allow rule"
                )

                denied_before = _nft_counter(denied_rule, "drop")
                denied_connected = _docker_tcp_connects(
                    service_ids["rpc-gateway"], "1.1.1.1", 443
                )
                denied_after = _nft_counter(denied_rule, "drop")
                assert not denied_connected, "unapproved Gateway egress unexpectedly connected"
                assert denied_after > denied_before, (
                    "unapproved Gateway egress did not match the nftables drop rule"
                )

                adapter_external_connected = _docker_tcp_connects(
                    service_ids["anvil-rpc-adapter"], "8.8.8.8", 443
                )
                anvil_external_connected = _docker_tcp_connects(
                    service_ids["anvil"], "8.8.8.8", 443
                )
                assert not adapter_external_connected
                assert not anvil_external_connected

                required_environment = (
                    "GITHUB_SHA",
                    "GITHUB_RUN_ID",
                    "GITHUB_RUN_ATTEMPT",
                    "RUNNER_TEMP",
                )
                assert all(os.environ.get(key) for key in required_environment), (
                    "packet_path_receipt_requires_github_actions_context"
                )
                receipt_path_value = os.environ.get(
                    "AEGISFORGE_PACKET_PATH_RECEIPT_PATH"
                )
                assert receipt_path_value, "packet_path_receipt_output_path_missing"

                receipt = {
                    "schema_version": 1,
                    "evidence_level": "DISPOSABLE_DOCKER_PACKET_PATH_TEST",
                    "runtime_session_id": str(uuid4()),
                    "compose_project": project,
                    "git_commit_sha": os.environ["GITHUB_SHA"],
                    "github_run_id": os.environ["GITHUB_RUN_ID"],
                    "github_run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
                    "containers": {
                        service: service_ids[service]
                        for service in ("rpc-gateway", "anvil-rpc-adapter", "anvil")
                    },
                    "networks": {
                        "fork-internal": {
                            "name": internal["Name"],
                            "id": internal["Id"],
                        },
                        "rpc-egress": {
                            "name": egress["Name"],
                            "id": egress["Id"],
                        },
                    },
                    "firewall": {
                        "table": FIREWALL_TABLE,
                        "ruleset_sha256": ruleset_sha256,
                        "counters": {
                            "gateway_approved_egress_allow_new": {
                                "before": allowed_before,
                                "after": allowed_after,
                            },
                            "gateway_unapproved_egress_drop": {
                                "before": denied_before,
                                "after": denied_after,
                            },
                        },
                    },
                    "probes": {
                        "gateway_approved_egress": {
                            "attempted": True,
                            "rule_matched": allowed_after > allowed_before,
                            "tcp_connected": approved_connected,
                        },
                        "gateway_unapproved_egress": {
                            "attempted": True,
                            "blocked": not denied_connected,
                            "rule_matched": denied_after > denied_before,
                        },
                        "adapter_gateway_internal": {
                            "connected": adapter_gateway_internal_connected
                        },
                        "anvil_adapter_internal": {
                            "connected": anvil_adapter_internal_connected
                        },
                        "adapter_external_egress": {
                            "blocked": not adapter_external_connected,
                            "default_route_absent": default_route_absent["anvil-rpc-adapter"],
                            "internal_network_only": (
                                internal["Internal"] is True
                                and set(adapter_networks) == {f"{project}_fork-internal"}
                            ),
                        },
                        "anvil_external_egress": {
                            "blocked": not anvil_external_connected,
                            "default_route_absent": default_route_absent["anvil"],
                            "internal_network_only": (
                                internal["Internal"] is True
                                and set(anvil_networks) == {f"{project}_fork-internal"}
                            ),
                        },
                    },
                }
                report = validate_packet_path_receipt(
                    receipt,
                    expected_commit_sha=os.environ["GITHUB_SHA"],
                    expected_run_id=os.environ["GITHUB_RUN_ID"],
                    expected_run_attempt=int(os.environ["GITHUB_RUN_ATTEMPT"]),
                )
                assert report.runtime_isolation_verified is False
                assert report.dynamic_verified is False
                assert report.confirmed is False
                output_path = Path(receipt_path_value)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(
                    json.dumps(receipt, sort_keys=True, indent=2) + "\n",
                    encoding="utf-8",
                )
        finally:
            try:
                subprocess.run(
                    compose + ["down", "--volumes", "--remove-orphans"],
                    cwd=ROOT,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=60,
                    check=False,
                )
            finally:
                try:
                    if firewall_applied:
                        subprocess.run(
                            [
                                "sudo", "-n", sys.executable, str(FIREWALL_SCRIPT),
                                "--remove",
                            ],
                            cwd=ROOT,
                            text=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            timeout=30,
                            check=True,
                        )
                finally:
                    subprocess.run(
                        ["docker", "image", "rm", "-f", image_tag],
                        cwd=ROOT,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=30,
                        check=False,
                    )
