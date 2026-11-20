#!/usr/bin/env python3
"""Install a narrow nftables egress guard for the AegisForge RPC Gateway.

Default mode validates the generated rules with nft -c and changes no host state.
Use --apply only after the matching Docker egress network exists and before
starting its Gateway container. This script never flushes the host ruleset.
"""
from __future__ import annotations

import argparse
import ipaddress
import subprocess
import sys


TABLE = "aegisforge_gateway_egress"


def validate_provider_network(value: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError("provider_cidr_invalid") from exc
    if (
        not isinstance(network, ipaddress.IPv4Network)
        or not network.is_global
        or network.prefixlen < 16
    ):
        raise ValueError("provider_cidr_not_public_unicast")
    return network


def build_rules(
    *,
    gateway_ip: str,
    provider_networks: list[ipaddress.IPv4Network],
) -> str:
    try:
        address = ipaddress.ip_address(gateway_ip)
    except ValueError as exc:
        raise ValueError("gateway_ip_invalid") from exc
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_private:
        raise ValueError("gateway_ip_must_be_private_ipv4")
    if not provider_networks:
        raise ValueError("provider_allowlist_empty")
    if any(
        not isinstance(network, ipaddress.IPv4Network)
        or not network.is_global
        or network.prefixlen < 16
        for network in provider_networks
    ):
        raise ValueError("provider_allowlist_invalid")

    elements = ", ".join(str(network) for network in sorted(provider_networks, key=str))
    gateway = str(address)
    return f"""table inet {TABLE} {{
    set approved_rpc_v4 {{
        type ipv4_addr
        flags interval
        elements = {{ {elements} }}
    }}

    chain forward_guard {{
        type filter hook forward priority -10; policy accept;

        # Only return traffic for Gateway-initiated sessions is admitted.
        ip daddr {gateway} ct state established,related accept
        ip daddr {gateway} drop

        # Permit new Gateway connections only to approved public RPC ranges.
        ip saddr {gateway} ct state established,related accept
        ip saddr {gateway} ip daddr @approved_rpc_v4 tcp dport 443 ct state new accept
        ip saddr {gateway} drop
    }}
}}
"""


def _run(command: list[str], *, input_text: str | None = None) -> None:
    subprocess.run(
        command,
        input=input_text,
        text=True,
        check=True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway-ip", default="172.31.240.2")
    parser.add_argument(
        "--provider-cidr",
        action="append",
        help="Public IPv4 CIDR published by the approved RPC provider; repeat as needed.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="Install the rules (requires root).")
    mode.add_argument("--remove", action="store_true", help="Remove only this dedicated table.")
    args = parser.parse_args(argv)

    if args.remove:
        _run(["nft", "delete", "table", "inet", TABLE])
        return 0

    if not args.provider_cidr:
        parser.error("--provider-cidr is required unless --remove is used")

    try:
        networks = [validate_provider_network(item) for item in args.provider_cidr]
        if len(set(networks)) != len(networks):
            raise ValueError("provider_allowlist_duplicate")
        rules = build_rules(
            gateway_ip=args.gateway_ip,
            provider_networks=networks,
        )
    except ValueError as exc:
        parser.error(str(exc))

    if args.apply:
        existing = subprocess.run(
            ["nft", "list", "table", "inet", TABLE],
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if existing.returncode == 0:
            parser.error(f"table_already_exists:{TABLE}; inspect it or remove it explicitly")
        _run(["nft", "-f", "-"], input_text=rules)
    else:
        _run(["nft", "-c", "-f", "-"], input_text=rules)
        print("nftables syntax valid; no host firewall state changed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
