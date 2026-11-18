import json

import pytest

from shared.discovery import (
    DiscoveryFinding,
    DiscoveryFindingError,
    FINDING_SCHEMA,
    enqueue_discovery_finding,
)
from shared.task_queue import TaskQueue


def finding(**overrides):
    values = {
        "chain": "base",
        "contract_address": "0x1234567890abcdef1234567890abcdef12345678",
        "finding_type": "unprotected_upgrade",
        "severity": "critical",
        "title": "Upgradeable contract lacks access control",
        "description": "The implementation upgrade path appears publicly callable.",
        "evidence": {"function": "upgradeTo", "source_line": 42},
        "observed_block": 123456,
        "source": "source_pattern",
    }
    values.update(overrides)
    return DiscoveryFinding(**values)


def test_finding_has_stable_fingerprint_across_observations():
    first = finding(observed_block=100, evidence={"line": 10})
    second = finding(observed_block=200, evidence={"line": 20})

    assert first.fingerprint == second.fingerprint


def test_finding_fingerprint_separates_chain_contract_and_pattern():
    original = finding()

    assert original.fingerprint != finding(chain="ethereum").fingerprint
    assert original.fingerprint != finding(
        contract_address="0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
    ).fingerprint
    assert original.fingerprint != finding(finding_type="reentrancy").fingerprint


def test_finding_rejects_invalid_contract_address():
    with pytest.raises(DiscoveryFindingError, match="contract_address_invalid"):
        finding(contract_address="not-an-address")


def test_finding_requires_evidence_and_valid_severity():
    with pytest.raises(DiscoveryFindingError, match="evidence_required"):
        finding(evidence={})
    with pytest.raises(DiscoveryFindingError, match="severity_invalid"):
        finding(severity="urgent")


def test_finding_payload_is_versioned_and_serializable():
    item = finding()
    payload = item.to_payload()

    assert payload["schema"] == FINDING_SCHEMA
    assert payload["fingerprint"] == item.fingerprint
    assert json.loads(item.to_task_description())["discovery_finding"] == payload


def test_enqueue_uses_canonical_queue_and_deduplicates(tmp_path):
    queue = TaskQueue(tmp_path / "agent_farm.db")
    try:
        item = finding()
        first_id, created = enqueue_discovery_finding(queue, item)
        second_id, second_created = enqueue_discovery_finding(
            queue, finding(observed_block=123999)
        )

        assert created is True
        assert second_created is False
        assert second_id == first_id
        row = queue.db.execute(
            "SELECT role, contract_address, fingerprint, description FROM queue WHERE id = ?",
            (first_id,),
        ).fetchone()
        assert row[:3] == ("source_researcher", item.contract_address, item.fingerprint)
        payload = json.loads(row[3])
        assert payload["task_type"] == "deep_research_intake"
        assert payload["discovery_finding"]["schema"] == FINDING_SCHEMA
    finally:
        queue.db.close()
