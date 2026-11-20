from pathlib import Path
import importlib.util
import ipaddress
import sys


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "deploy" / "anvil-fork" / "install_egress_firewall.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("aegisforge_egress_firewall", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_firewall_rules_allow_only_approved_ipv4_rpc_destinations():
    module = _load_module()
    rules = module.build_rules(
        gateway_ip="172.31.240.2",
        provider_networks=[ipaddress.ip_network("8.8.8.8/32")],
    )

    assert "table inet aegisforge_gateway_egress" in rules
    assert "ip saddr 172.31.240.2" in rules
    assert "ip saddr 172.31.240.2 ip daddr @approved_rpc_v4 tcp dport 443 ct state established,related counter accept" in rules
    assert "ip daddr @approved_rpc_v4 tcp dport 443 ct state new counter accept" in rules
    assert "ip saddr 172.31.240.2 ct state established,related accept" not in rules
    assert "ip saddr 172.31.240.2 drop" in rules
    assert "ip daddr 172.31.240.2 drop" in rules
    assert 'iifname "br-aegisforge" ip saddr 172.31.240.2 ip daddr @approved_rpc_v4 tcp dport 443 ct state established,related counter accept' in rules
    assert 'iifname "br-aegisforge" ip saddr 172.31.240.2 ip daddr @approved_rpc_v4 tcp dport 443 ct state new counter accept' in rules
    assert 'oifname "br-aegisforge" ip saddr @approved_rpc_v4 ip daddr 172.31.240.2 ct state established,related counter accept' in rules
    assert 'iifname "br-aegisforge" ip saddr 172.31.240.2 counter drop' in rules
    assert 'oifname "br-aegisforge" ip daddr 172.31.240.2 counter drop' in rules


def test_firewall_rejects_invalid_or_non_ipv4_provider_ranges():
    module = _load_module()

    for value in ("0.0.0.0/0", "8.0.0.0/8", "127.0.0.1/32", "169.254.1.1/32"):
        try:
            module.validate_provider_network(value)
        except ValueError:
            pass
        else:
            raise AssertionError(f"unsafe provider range accepted: {value}")

    try:
        module.validate_provider_network("2001:db8::1/128")
    except ValueError:
        pass
    else:
        raise AssertionError("IPv6 provider range must be rejected")


def test_firewall_rules_do_not_flush_or_replace_other_host_firewall_state():
    module = _load_module()
    rules = module.build_rules(
        gateway_ip="172.31.240.2",
        provider_networks=[ipaddress.ip_network("8.8.8.8/32")],
    )

    assert "flush ruleset" not in rules
    assert "flush table" not in rules
    assert "delete table" not in rules


def test_firewall_requires_at_least_one_approved_provider_network():
    module = _load_module()
    try:
        module.build_rules(
            gateway_ip="172.31.240.2",
            provider_networks=[],
        )
    except ValueError:
        pass
    else:
        raise AssertionError("empty provider allowlist must fail closed")


def test_firewall_table_can_be_removed_without_provider_cidr(monkeypatch):
    module = _load_module()
    observed = {}

    def fake_run(command, *, input_text=None):
        observed["command"] = command
        observed["input_text"] = input_text

    monkeypatch.setattr(module, "_run", fake_run)
    assert module.main(["--remove"]) == 0
    assert observed["command"] == ["nft", "delete", "table", "inet", "aegisforge_gateway_egress"]
    assert observed["input_text"] is None

def test_firewall_default_mode_only_checks_rules_without_applying(monkeypatch, capsys):
    module = _load_module()
    observed = {}

    def fake_run(command, *, input_text=None):
        observed["command"] = command
        observed["input_text"] = input_text

    monkeypatch.setattr(module, "_run", fake_run)
    assert module.main(["--provider-cidr", "8.8.8.8/32"]) == 0

    assert observed["command"] == ["nft", "-c", "-f", "-"]
    assert "table inet aegisforge_gateway_egress" in observed["input_text"]
    assert "nftables syntax valid" in capsys.readouterr().out

