"""Disposable Docker Compose runtime checks for the Anvil fork network boundary.

Runs only on an ephemeral CI Docker host. It never installs or changes host
firewall rules and always tears down its uniquely named Compose project.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy" / "anvil-fork" / "compose.yaml"
OVERRIDE = ROOT / "tests" / "fixtures" / "anvil-fork-compose-runtime.override.yaml"
DOCKERFILE = ROOT / "deploy" / "anvil-fork" / "Dockerfile.rpc-sidecar"


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


def _docker_exec(container_id: str, code: str, *, expect_success: bool) -> None:
    result = subprocess.run(
        ["docker", "exec", container_id, "python", "-c", code],
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


@pytest.mark.skipif(
    shutil.which("docker") is None or shutil.which("ip") is None,
    reason="requires Docker Engine, Docker Compose v2 and iproute2 on an ephemeral CI host",
)
def test_real_compose_network_membership_and_internal_service_egress():
    python_image = os.environ.get("AEGISFORGE_PYTHON_IMAGE", "")
    assert "@sha256:" in python_image, "CI must provide a digest-pinned Python base image"

    project = f"aegisforge-compose-runtime-{os.getpid()}"
    image_tag = "aegisforge-rpc-sidecar:local"
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

            # Internal RPC paths must work over the real Docker bridge.
            _docker_exec(
                service_ids["anvil"],
                "import socket; s=socket.create_connection(('anvil-rpc-adapter',8546),3); s.close()",
                expect_success=True,
            )
            _docker_exec(
                service_ids["anvil-rpc-adapter"],
                "import socket; s=socket.create_connection(('rpc-gateway',8545),3); s.close()",
                expect_success=True,
            )

            # Internal-only containers must not have a usable public IPv4 egress path.
            external_probe = (
                "import socket; s=socket.socket(); s.settimeout(2); "
                "s.connect(('1.1.1.1',443)); s.close()"
            )
            _docker_exec(service_ids["anvil-rpc-adapter"], external_probe, expect_success=False)
            _docker_exec(service_ids["anvil"], external_probe, expect_success=False)
        finally:
            subprocess.run(
                compose + ["down", "--volumes", "--remove-orphans"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
                check=False,
            )
            subprocess.run(
                ["docker", "image", "rm", "-f", image_tag],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False,
            )
