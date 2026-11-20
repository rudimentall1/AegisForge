"""Runtime packet-path checks for the Anvil Gateway nftables policy.

The test creates disposable Linux network namespaces and installs the policy
inside the router namespace only. It never changes the runner host firewall.
"""
from __future__ import annotations

import importlib.util
import ipaddress
import os
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
                "sys.exit(0 if (lambda: (s.connect((sys.argv[1],int(sys.argv[2])))) is None)() else 1)"
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
    namespaces = ("aegis-router", "aegis-gateway", "aegis-provider", "aegis-adapter")
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

        _ns("aegis-router", "ip", "addr", "add", "172.31.240.1/28", "dev", "br-aegisforge")
        _ns("aegis-gateway", "ip", "addr", "add", "172.31.240.2/28", "dev", "eth0")
        _ns("aegis-router", "ip", "addr", "add", "198.18.0.1/30", "dev", "provider0")
        _ns("aegis-provider", "ip", "addr", "add", "198.18.0.2/30", "dev", "eth0")
        _ns("aegis-provider", "ip", "addr", "add", "8.8.8.8/32", "dev", "lo")
        _ns("aegis-provider", "ip", "addr", "add", "1.1.1.1/32", "dev", "lo")
        _ns("aegis-gateway", "ip", "addr", "add", "172.30.240.2/30", "dev", "internal0")
        _ns("aegis-adapter", "ip", "addr", "add", "172.30.240.3/30", "dev", "eth0")

        for namespace, interface in (
            ("aegis-router", "br-aegisforge"),
            ("aegis-router", "provider0"),
            ("aegis-gateway", "eth0"),
            ("aegis-gateway", "internal0"),
            ("aegis-provider", "eth0"),
            ("aegis-adapter", "eth0"),
        ):
            _ns(namespace, "ip", "link", "set", interface, "up")

        _ns("aegis-router", "sysctl", "-w", "net.ipv4.ip_forward=1")
        _ns("aegis-router", "sysctl", "-w", "net.ipv4.conf.all.rp_filter=0")
        _ns("aegis-gateway", "ip", "route", "add", "default", "via", "172.31.240.1")
        _ns("aegis-router", "ip", "route", "add", "8.8.8.8/32", "dev", "provider0")
        _ns("aegis-router", "ip", "route", "add", "1.1.1.1/32", "dev", "provider0")
        _ns("aegis-provider", "ip", "route", "add", "172.31.240.0/28", "via", "198.18.0.1")

        provider_server = (
            "import socket,threading; "
            "servers=[]; "
            "[(lambda s: (s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1),"
            "s.bind(('0.0.0.0',p)),s.listen(),servers.append(s)))(socket.socket()) "
            "for p in (443,444)]; "
            "[(threading.Thread(target=lambda s=s: "
            "[(lambda c: c.close())(s.accept()[0]) for _ in iter(int,1)],daemon=True).start()) "
            "for s in servers]; "
            "__import__('threading').Event().wait()"
        )
        internal_server = (
            "import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); "
            "s.bind(('172.30.240.2',8545)); s.listen(); "
            "while True: "
            " c,_=s.accept(); c.sendall(b'INTERNAL_RPC_OK'); c.close()"
        )
        processes.append(subprocess.Popen(
            ["ip", "netns", "exec", "aegis-provider", "python", "-c", provider_server],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ))
        processes.append(subprocess.Popen(
            ["ip", "netns", "exec", "aegis-gateway", "python", "-c", internal_server],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ))
        _wait_for_listener("aegis-provider", "8.8.8.8", 443)
        _wait_for_listener("aegis-gateway", "172.30.240.2", 8545)

        module = _firewall_module()
        rules = module.build_rules(
            gateway_ip="172.31.240.2",
            provider_networks=[ipaddress.ip_network("8.8.8.8/32")],
        )
        _ns("aegis-router", "nft", "-f", "-", input_text=rules)

        allowed = _ns(
            "aegis-gateway", "python", "-c",
            "import socket; s=socket.create_connection(('8.8.8.8',443),2); s.close()",
            check=False,
        )
        assert allowed.returncode == 0, allowed.stderr

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
