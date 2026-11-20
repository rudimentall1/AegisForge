from __future__ import annotations

import copy

import pytest

from agents.security_checker.packet_path_evidence import (
    PacketPathEvidenceError,
    validate_packet_path_receipt,
)


COMMIT = "a" * 40
RUN_ID = "44712559237"
RUN_ATTEMPT = 1


def _receipt():
    return {
        "schema_version": 1,
        "evidence_level": "DISPOSABLE_DOCKER_PACKET_PATH_TEST",
        "runtime_session_id": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
        "compose_project": "aegisforge-compose-runtime-12345",
        "git_commit_sha": COMMIT,
        "github_run_id": RUN_ID,
        "github_run_attempt": RUN_ATTEMPT,
        "containers": {
            "rpc-gateway": "1" * 64,
            "anvil-rpc-adapter": "2" * 64,
            "anvil": "3" * 64,
        },
        "networks": {
            "fork-internal": {
                "name": "aegisforge-compose-runtime-12345_fork-internal",
                "id": "4" * 64,
            },
            "rpc-egress": {
                "name": "aegisforge-compose-runtime-12345_rpc-egress",
                "id": "5" * 64,
            },
        },
        "firewall": {
            "table": "aegisforge_gateway_egress",
            "ruleset_sha256": "6" * 64,
            "counters": {
                "gateway_approved_egress_allow_new": {"before": 2, "after": 3},
                "gateway_unapproved_egress_drop": {"before": 4, "after": 5},
            },
        },
        "probes": {
            "gateway_approved_egress": {
                "attempted": True,
                "rule_matched": True,
                "tcp_connected": False,
            },
            "gateway_unapproved_egress": {
                "attempted": True,
                "blocked": True,
                "rule_matched": True,
            },
            "adapter_gateway_internal": {"connected": True},
            "anvil_adapter_internal": {"connected": True},
            "adapter_external_egress": {
                "blocked": True,
                "default_route_absent": True,
                "internal_network_only": True,
            },
            "anvil_external_egress": {
                "blocked": True,
                "default_route_absent": True,
                "internal_network_only": True,
            },
        },
    }


def _validate(receipt):
    return validate_packet_path_receipt(
        receipt,
        expected_commit_sha=COMMIT,
        expected_run_id=RUN_ID,
        expected_run_attempt=RUN_ATTEMPT,
    )


def test_packet_path_receipt_validates_observed_ci_evidence_without_promoting_finding():
    report = _validate(_receipt())

    assert report.state == "PACKET_PATH_RECEIPT_VALIDATED"
    assert report.runtime_session_id == "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
    assert report.services == ("rpc-gateway", "anvil-rpc-adapter", "anvil")
    assert report.compose_project == "aegisforge-compose-runtime-12345"
    assert report.runtime_isolation_verified is False
    assert report.dynamic_verified is False
    assert report.confirmed is False


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda item: item.pop("runtime_session_id"), "packet_path_receipt_schema_invalid"),
        (lambda item: item.__setitem__("git_commit_sha", "b" * 40), "packet_path_commit_binding_invalid"),
        (lambda item: item.__setitem__("github_run_id", "1"), "packet_path_run_binding_invalid"),
        (lambda item: item["containers"].__setitem__("anvil", "x" * 64), "packet_path_container_id_invalid"),
        (lambda item: item["networks"]["rpc-egress"].__setitem__("name", "untrusted"), "packet_path_network_binding_invalid"),
        (lambda item: item["firewall"].__setitem__("ruleset_sha256", "z" * 64), "packet_path_ruleset_digest_invalid"),
        (lambda item: item["firewall"]["counters"]["gateway_approved_egress_allow_new"].__setitem__("after", 2), "packet_path_counter_delta_missing"),
        (lambda item: item["firewall"]["counters"]["gateway_unapproved_egress_drop"].__setitem__("after", 4), "packet_path_counter_delta_missing"),
        (lambda item: item["probes"]["anvil_adapter_internal"].__setitem__("connected", False), "packet_path_probe_incomplete"),
        (lambda item: item["probes"]["anvil_external_egress"].__setitem__("internal_network_only", False), "packet_path_probe_incomplete"),
    ],
)
def test_packet_path_receipt_rejects_unbound_or_incomplete_evidence(mutate, reason):
    receipt = copy.deepcopy(_receipt())
    mutate(receipt)

    with pytest.raises(PacketPathEvidenceError, match=reason):
        _validate(receipt)


def test_packet_path_receipt_rejects_missing_or_extra_service_and_probe():
    receipt = _receipt()
    receipt["containers"].pop("anvil")
    with pytest.raises(PacketPathEvidenceError, match="packet_path_service_inventory_invalid"):
        _validate(receipt)

    receipt = _receipt()
    receipt["probes"]["unexpected"] = {"connected": True}
    with pytest.raises(PacketPathEvidenceError, match="packet_path_probe_inventory_invalid"):
        _validate(receipt)


def test_packet_path_receipt_rejects_mismatched_expected_workflow_context():
    with pytest.raises(PacketPathEvidenceError, match="packet_path_commit_binding_invalid"):
        validate_packet_path_receipt(
            _receipt(),
            expected_commit_sha="b" * 40,
            expected_run_id=RUN_ID,
            expected_run_attempt=RUN_ATTEMPT,
        )

    with pytest.raises(PacketPathEvidenceError, match="packet_path_run_binding_invalid"):
        validate_packet_path_receipt(
            _receipt(),
            expected_commit_sha=COMMIT,
            expected_run_id="44712559105",
            expected_run_attempt=RUN_ATTEMPT,
        )



def test_packet_path_receipt_rejects_unexpected_compose_project_name():
    receipt = _receipt()
    receipt["compose_project"] = "untrusted-project"

    with pytest.raises(PacketPathEvidenceError, match="packet_path_project_binding_invalid"):
        _validate(receipt)
