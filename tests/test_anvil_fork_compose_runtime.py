"""Disposable Docker Compose runtime checks for the Anvil fork network boundary.

Runs on an ephemeral CI Docker host. The dedicated nftables table is applied
only when an explicit GitHub-hosted-runner flag is set, and is always removed.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy" / "anvil-fork" / "compose.yaml"
OVERRIDE = ROOT / "tests" / "fixtures" / "anvil-fork-compose-runtime.override.yaml"
DOCKERFILE = ROOT / "deploy" / "anvil-fork" / "Dockerfile.rpc-sidecar"
FIREWALL_SCRIPT = ROOT / "deploy" / "anvil-fork" / "install_egress_firewall.py"
FIREWALL_TABLE = "aegisforge_gateway_egress"


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

            # Adapter-to-Gateway traffic must work over the real Docker bridge.
            # Anvil-to-Adapter TCP behavior is covered by the namespace packet-path
            # test; this container-level check avoids assuming extra tools in Foundry.
            _docker_exec(
                service_ids["anvil-rpc-adapter"],
                "import socket; s=socket.create_connection(('rpc-gateway',8545),3); s.close()",
                expect_success=True,
            )

            # Neither internal-only service may have a default route. The
            # Adapter additionally performs a real failed-connect probe from its
            # own network namespace; Anvil's route table is read without assuming
            # Python, Bash, curl, or netcat in the official Foundry image.
            _docker_exec(
                service_ids["anvil-rpc-adapter"],
                "rows=open('/proc/net/route',encoding='ascii').read().splitlines()[1:]; "
                "assert not any(line.split()[1]=='00000000' for line in rows), "
                "'internal-only service unexpectedly has a default route'",
                expect_success=True,
            )
            anvil_routes = _docker_exec_output(service_ids["anvil"], ["cat", "/proc/net/route"])
            anvil_route_rows = [line.split() for line in anvil_routes.splitlines()[1:]]
            assert not any(len(row) > 1 and row[1] == "00000000" for row in anvil_route_rows), (
                "Anvil unexpectedly has a default route"
            )
            _docker_exec(
                service_ids["anvil-rpc-adapter"],
                "import socket; s=socket.socket(); s.settimeout(1); "
                "s.connect(('8.8.8.8',443))",
                expect_success=False,
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
                allowed_before = _nft_counter(allowed_rule, "accept")
                denied_before = _nft_counter(denied_rule, "drop")

                # Counters prove that packets reached the host firewall and
                # matched the intended rule; TCP handshake success is irrelevant.
                probe = (
                    "import socket,sys; "
                    "s=socket.socket(); s.settimeout(1); "
                    "exec('try:\\n s.connect((sys.argv[1],443))\\n"
                    "except OSError:\\n pass\\nfinally:\\n s.close()')"
                )
                for destination in ("8.8.8.8", "1.1.1.1"):
                    _docker_exec(
                        service_ids["rpc-gateway"],
                        probe,
                        expect_success=True,
                        args=(destination,),
                    )

                assert _nft_counter(allowed_rule, "accept") > allowed_before, (
                    "approved Gateway egress did not match the nftables allow rule"
                )
                assert _nft_counter(denied_rule, "drop") > denied_before, (
                    "unapproved Gateway egress did not match the nftables drop rule"
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
