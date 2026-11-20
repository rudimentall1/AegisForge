"""Runtime packet-path checks for the Anvil Gateway nftables policy.

The test creates disposable Linux network namespaces and installs the policy
inside the router namespace only. It never changes the runner host firewall.
"""
from __future__ import annotations

import importlib.util
import ipaddress
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
FIREWALL_PATH = ROOT / "deploy" / "anvil-fork" / "install_egress_firewall.py"


def _firewall_module():
    spec = importlib.util.spec_from_file_location("aegisforge_runtime_firewall", FIREWALL_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _run(*args: str, check: bool = True, input_text: str | None = None):
    return subprocess.run(
        list(args),
        check=check,
        text=True,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )


def _ns(
    namespace: str,
    *args: str,
    check: bool = True,
    input_text: str | None = None,
):
    return _run(
        "ip", "netns", "exec", namespace, *args,
        check=check, input_text=input_text,
    )


def _nft_counter(namespace: str, rule_fragment: str, verdict: str) -> int:
    output = _ns(\n        namespace, "nft", "list", "chain", "inet",\n        "aegisforge_gateway_egress", "forward_guard"\n    ).stdout
    for line in output.splitlines():
        if rule_fragment in line and line.rstrip().endswith(verdict):
            match = re.search(r"counter packets (\d+)", line)
            if match:
                return int(match.group(1))
    raise AssertionError(f"firewall_rule_counter_missing:{rule_fragment}")


def _wait_for_listener(namespace: str, address: str, port: int) -> None:
    deadline = time.monotonic() + 5
    last_error = None
    while time.monotonic() < deadline:
        result = _ns(
            namespace,
            "python",
            "-c",
            (
                "import socket,sys; "
                "s=socket.socket(); s.settimeout(.3); "
                "s.connect((sys.argv[1],int(sys.argv[2])))"
            ),
            address,
            str(port),
            check=False,
        )
        if result.returncode == 0:
            return
        last_error = result.stderr
        time.sleep(0.05)
    raise AssertionError(f"listener_not_ready:{address}:{port}:{last_error}")


@pytest.mark.skipif(
    os.name != "posix"
    or os.geteuid() != 0
    or any(shutil.which(command) is None for command in ("ip", "nft", "python")),
    reason="requires root, iproute2 and nftables; CI runs this in an ephemeral Ubuntu VM",
)
def test_gateway_egress_firewall_allows_only_approved_https_and_preserves_internal_rpc():
    namespaces = ("aegis-router", "aegis-gateway", "aegis-provider", "aegis-adapter", "aegis-anvil")
    processes: list[subprocess.Popen] = []

    def add_veth(left_ns: str, left_name: str, right_ns: str, right_name: str):
        host_left = f"x{left_name.replace('-', '')}"[:14]
        host_right = f"x{right_name.replace('-', '')}"[:14]
        _run("ip", "link", "add", host_left, "type", "veth", "peer", "name", host_right)
        _run("ip", "link", "set", host_left, "netns", left_ns)
        _run("ip", "link", "set", host_right, "netns", right_ns)
        _ns(left_ns, "ip", "link", "set", host_left, "name", left_name)
        _ns(right_ns, "ip", "link", "set", host_right, "name", right_name)

    try:
        for namespace in namespaces:
            _run("ip", "netns", "add", namespace)
            _ns(namespace, "ip", "link", "set", "lo", "up")

        # This point-to-point link uses the exact interface name matched by
        # the production rules, while remaining wholly inside the test router.
        add_veth("aegis-router", "br-aegisforge", "aegis-gateway", "eth0")
        add_veth("aegis-router", "provider0", "aegis-provider", "eth0")
        add_veth("aegis-gateway", "internal0", "aegis-adapter", "eth0")
        add_veth("aegis-gateway", "internal1", "aegis-anvil", "eth0")
        _ns("aegis-gateway", "ip", "link", "add", "br-internal", "type", "bridge")
        _ns("aegis-gateway", "ip", "link", "set", "internal0", "master", "br-internal")
        _ns("aegis-gateway", "ip", "link", "set", "internal1", "master", "br-internal")

        _ns("aegis-router", "ip", "addr", "add", "172.31.240.1/28", "dev", "br-aegisforge")
        _ns("aegis-gateway", "ip", "addr", "add", "172.31.240.2/28", "dev", "eth0")
        _ns("aegis-router", "ip", "addr", "add", "198.18.0.1/30", "dev", "provider0")
        _ns("aegis-provider", "ip", "addr", "add", "198.18.0.2/30", "dev", "eth0")
        _ns("aegis-provider", "ip", "addr", "add", "8.8.8.8/32", "dev", "lo")
        _ns("aegis-provider", "ip", "addr", "add", "1.1.1.1/32", "dev", "lo")
        _ns("aegis-gateway", "ip", "addr", "add", "172.30.240.2/29", "dev", "br-internal")
        _ns("aegis-adapter", "ip", "addr", "add", "172.30.240.3/29", "dev", "eth0")
        _ns("aegis-anvil", "ip", "addr", "add", "172.30.240.4/29", "dev", "eth0")

        for namespace, interface in (
            ("aegis-router", "br-aegisforge"),
            ("aegis-router", "provider0"),
            ("aegis-gateway", "eth0"),
            ("aegis-gateway", "internal0"),
            ("aegis-gateway", "internal1"),
            ("aegis-gateway", "br-internal"),
            ("aegis-provider", "eth0"),
            ("aegis-adapter", "eth0"),
            ("aegis-anvil", "eth0"),
        ):
            _ns(namespace, "ip", "link", "set", interface, "up")

        _ns("aegis-router", "sysctl", "-w", "net.ipv4.ip_forward=1")
        _ns("aegis-router", "sysctl", "-w", "net.ipv4.conf.all.rp_filter=0")
        _ns("aegis-gateway", "sysctl", "-w", "net.ipv4.ip_forward=1")
        _ns("aegis-gateway", "sysctl", "-w", "net.ipv4.conf.all.rp_filter=0")
        _ns("aegis-gateway", "ip", "route", "add", "default", "via", "172.31.240.1")
        _ns("aegis-adapter", "ip", "route", "add", "default", "via", "172.30.240.2")
        _ns("aegis-anvil", "ip", "route", "add", "default", "via", "172.30.240.2")
        _ns("aegis-router", "ip", "route", "add", "8.8.8.8/32", "dev", "provider0")
        _ns("aegis-router", "ip", "route", "add", "1.1.1.1/32", "dev", "provider0")
        _ns("aegis-provider", "ip", "route", "add", "172.31.240.0/28", "via", "198.18.0.1")

        provider_server = """
import socket
import threading
def serve(port):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen()
    while True:
        connection, _ = server.accept()
        connection.close()
for port in (443, 444):
    threading.Thread(target=serve, args=(port,), daemon=True).start()
threading.Event().wait()
"""
        internal_server = """
import socket
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("172.30.240.2", 8545))
server.listen()
while True:
    connection, _ = server.accept()
    connection.sendall(b"INTERNAL_RPC_OK")
    connection.close()
"""
        adapter_server = """
import socket
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("172.30.240.3", 8546))
server.listen()
while True:
    connection, _ = server.accept()
    connection.sendall(b"ANVIL_ADAPTER_RPC_OK")
    connection.close()
"""
        processes.append(subprocess.Popen(
            ["ip", "netns", "exec", "aegis-provider", "python", "-c", provider_server],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ))
        processes.append(subprocess.Popen(
            ["ip", "netns", "exec", "aegis-gateway", "python", "-c", internal_server],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ))
        processes.append(subprocess.Popen(
            ["ip", "netns", "exec", "aegis-adapter", "python", "-c", adapter_server],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ))
        _wait_for_listener("aegis-provider", "8.8.8.8", 443)
        _wait_for_listener("aegis-gateway", "172.30.240.2", 8545)
        _wait_for_listener("aegis-adapter", "172.30.240.3", 8546)

        module = _firewall_module()
        rules = module.build_rules(
            gateway_ip="172.31.240.2",
            provider_networks=[ipaddress.ip_network("8.8.8.8/32")],
        )
        _ns("aegis-router", "nft", "-f", "-", input_text=rules)
        provider_reply_rule = (
            'oifname "br-aegisforge" ip saddr @approved_rpc_v4 '
            'ip daddr 172.31.240.2 ct state established,related'
        )
        provider_reply_before = _nft_counter(
            "aegis-router", provider_reply_rule, "accept"
        )

        allowed = _ns(
            "aegis-gateway", "python", "-c",
            "import socket; s=socket.create_connection(('8.8.8.8',443),2); s.close()",
            check=False,
        )
        assert allowed.returncode == 0, allowed.stderr
        assert _nft_counter(
            "aegis-router", provider_reply_rule, "accept"
        ) > provider_reply_before, (
            "approved provider reply did not match the established-return allow rule"
        )

        denied_ip = _ns(
            "aegis-gateway", "python", "-c",
            "import socket; s=socket.create_connection(('1.1.1.1',443),1); s.close()",
            check=False,
        )
        assert denied_ip.returncode != 0, "unapproved provider IP unexpectedly reachable"

        denied_port = _ns(
            "aegis-gateway", "python", "-c",
            "import socket; s=socket.create_connection(('8.8.8.8',444),1); s.close()",
            check=False,
        )
        assert denied_port.returncode != 0, "non-HTTPS provider port unexpectedly reachable"

        internal = _ns(
            "aegis-adapter", "python", "-c",
            (
                "import socket; s=socket.create_connection(('172.30.240.2',8545),2); "
                "assert s.recv(64)==b'INTERNAL_RPC_OK'; s.close()"
            ),
            check=False,
        )
        assert internal.returncode == 0, internal.stderr

        anvil_to_adapter = _ns(
            "aegis-anvil", "python", "-c",
            (
                "import socket; s=socket.create_connection(('172.30.240.3',8546),2); "
                "assert s.recv(64)==b'ANVIL_ADAPTER_RPC_OK'; s.close()"
            ),
            check=False,
        )
        assert anvil_to_adapter.returncode == 0, anvil_to_adapter.stderr

        # Give both internal services a real default route through the Gateway.
        # Their external packets therefore traverse the router's production
        # br-aegisforge policy and must be rejected by source-IP enforcement.
        for isolated_service in ("aegis-adapter", "aegis-anvil"):
            external_attempt = _ns(
                isolated_service, "python", "-c",
                "import socket; socket.create_connection(('8.8.8.8',443),1)",
                check=False,
            )
            assert external_attempt.returncode != 0, (
                f"{isolated_service} unexpectedly reached the external provider endpoint"
            )
    finally:
        for process in processes:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        for namespace in namespaces:
            subprocess.run(
                ["ip", "netns", "del", namespace],
                check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5,
            )
