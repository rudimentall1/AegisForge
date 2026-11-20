import pytest

from agents.security_checker.fork_runtime_evidence import (
    RuntimeEvidenceError,
    validate_runtime_observations,
)


PROJECT = "aegisforge-anvil-fork"
SERVICES = ("rpc-gateway", "anvil-rpc-adapter", "anvil")


def _container(service, *, healthy=True):
    state = {"Running": True, "Status": "running"}
    if service != "anvil":
        state["Health"] = {"Status": "healthy" if healthy else "starting"}
    return {
        "Id": ({"rpc-gateway": "1", "anvil-rpc-adapter": "2", "anvil": "3"}[service] * 64),
        "Config": {
            "Labels": {
                "com.docker.compose.project": PROJECT,
                "com.docker.compose.service": service,
            },
        },
        "State": state,
        "HostConfig": {
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "PidsLimit": {"rpc-gateway": 64, "anvil-rpc-adapter": 64, "anvil": 128}[service],
            "Memory": {"rpc-gateway": 268435456, "anvil-rpc-adapter": 268435456, "anvil": 1073741824}[service],
            "NanoCpus": {"rpc-gateway": 1000000000, "anvil-rpc-adapter": 1000000000, "anvil": 2000000000}[service],
            "Privileged": False,
            "PortBindings": None,
            "Binds": None,
        },
        "NetworkSettings": {
            "Networks": {
                "aegisforge-anvil-fork_fork-internal": {},
                **({"aegisforge-anvil-fork_rpc-egress": {}} if service == "rpc-gateway" else {}),
            },
        },
        "Mounts": [
            {"Type": "tmpfs", "Destination": "/tmp", "RW": True},
        ],
    }


def _network(name, *, internal, subnet):
    return {
        "Name": name,
        "Driver": "bridge",
        "Internal": internal,
        "EnableIPv6": False,
        "Options": (
            {}
            if internal
            else {
                "com.docker.network.bridge.enable_icc": "false",
                "com.docker.network.bridge.name": "br-aegisforge",
            }
        ),
        "IPAM": {"Config": [{"Subnet": subnet}]},
        "Labels": {
            "com.docker.compose.project": PROJECT,
            "com.docker.compose.network": name.rsplit("_", 1)[-1],
        },
    }


def _observations():
    return {
        "containers": [_container(service) for service in SERVICES],
        "networks": [
            _network("aegisforge-anvil-fork_fork-internal", internal=True, subnet="172.30.240.0/24"),
            _network("aegisforge-anvil-fork_rpc-egress", internal=False, subnet="172.31.240.0/28"),
        ],
        "firewall": {
            "table_present": True,
            "family": "inet",
            "name": "aegisforge_gateway_egress",
        },
    }


def test_runtime_observations_validate_but_do_not_claim_packet_path_verification():
    report = validate_runtime_observations(_observations(), expected_project=PROJECT)

    assert report.state == "RUNTIME_OBSERVATIONS_VALIDATED"
    assert report.services == SERVICES
    assert report.runtime_started is True
    assert report.runtime_isolation_verified is False
    assert report.dynamic_verified is False
    assert report.confirmed is False


def test_runtime_observations_reject_missing_or_duplicate_service():
    observations = _observations()
    observations["containers"].pop()

    with pytest.raises(RuntimeEvidenceError, match="runtime_service_inventory_invalid"):
        validate_runtime_observations(observations, expected_project=PROJECT)

    observations = _observations()
    observations["containers"].append(_container("anvil"))

    with pytest.raises(RuntimeEvidenceError, match="runtime_service_inventory_invalid"):
        validate_runtime_observations(observations, expected_project=PROJECT)


def test_runtime_observations_reject_unhealthy_dependency():
    observations = _observations()
    observations["containers"][0] = _container("rpc-gateway", healthy=False)

    with pytest.raises(RuntimeEvidenceError, match="runtime_service_unhealthy"):
        validate_runtime_observations(observations, expected_project=PROJECT)


def test_runtime_observations_reject_extra_network_attachment():
    observations = _observations()
    observations["containers"][2]["NetworkSettings"]["Networks"]["attacker_net"] = {}

    with pytest.raises(RuntimeEvidenceError, match="runtime_network_attachment_invalid"):
        validate_runtime_observations(observations, expected_project=PROJECT)


def test_runtime_observations_reject_gateway_egress_attachment_on_anvil_or_adapter():
    observations = _observations()
    observations["containers"][1]["NetworkSettings"]["Networks"]["aegisforge-anvil-fork_rpc-egress"] = {}

    with pytest.raises(RuntimeEvidenceError, match="runtime_network_attachment_invalid"):
        validate_runtime_observations(observations, expected_project=PROJECT)


def test_runtime_observations_reject_privileged_or_writable_container():
    observations = _observations()
    observations["containers"][2]["HostConfig"]["Privileged"] = True

    with pytest.raises(RuntimeEvidenceError, match="runtime_container_hardening_invalid"):
        validate_runtime_observations(observations, expected_project=PROJECT)

    observations = _observations()
    observations["containers"][0]["HostConfig"]["ReadonlyRootfs"] = False
    with pytest.raises(RuntimeEvidenceError, match="runtime_container_hardening_invalid"):
        validate_runtime_observations(observations, expected_project=PROJECT)


def test_runtime_observations_reject_invalid_network_and_missing_firewall_table():
    observations = _observations()
    observations["networks"][0]["Internal"] = False

    with pytest.raises(RuntimeEvidenceError, match="runtime_network_topology_invalid"):
        validate_runtime_observations(observations, expected_project=PROJECT)

    observations = _observations()
    observations["firewall"]["table_present"] = False
    with pytest.raises(RuntimeEvidenceError, match="runtime_firewall_table_missing"):
        validate_runtime_observations(observations, expected_project=PROJECT)


def test_runtime_observations_reject_wrong_project_label():
    observations = _observations()
    observations["containers"][0]["Config"]["Labels"]["com.docker.compose.project"] = "other"

    with pytest.raises(RuntimeEvidenceError, match="runtime_project_binding_invalid"):
        validate_runtime_observations(observations, expected_project=PROJECT)
