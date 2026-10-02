from datetime import datetime, timedelta, timezone

import pytest

from shared.capability_grant import (
    CapabilityGrantError,
    consume_capability_grant,
    evidence_hash,
    intent_hash,
    issue_capability_grant,
)
from shared.capability_policy import ActionIntent


def _intent(**overrides):
    values = {
        "role": "developer",
        "action": "deploy",
        "target": "staging",
        "resource": "service",
        "destination": "staging",
        "data_scope": "artifact",
        "read_only": False,
    }
    values.update(overrides)
    return ActionIntent(**values)


def test_hashes_are_deterministic():
    intent = _intent()
    assert intent_hash(intent) == intent_hash(intent.to_dict())
    assert evidence_hash(["b", "a"]) == evidence_hash(["a", "b"])


def test_issue_binds_intent_and_evidence():
    intent = _intent()
    grant = issue_capability_grant("task-1", intent, "policy-v1", ["ev-2", "ev-1"], "staging/service")
    assert grant.status == "ACTIVE"
    assert grant.task_id == "task-1"
    assert grant.evidence_ids == ("ev-1", "ev-2")
    assert grant.authorized_action == "deploy"
    assert consume_capability_grant(grant, intent, ["ev-1", "ev-2"])


def test_intent_tampering_is_rejected():
    grant = issue_capability_grant("task-1", _intent(), "policy-v1")
    with pytest.raises(CapabilityGrantError, match="intent_hash_mismatch"):
        consume_capability_grant(grant, _intent(target="production"))


def test_execution_parameters_are_bound_to_grant():
    intent = _intent(parameters={"title": "safe", "body": "approved"})
    grant = issue_capability_grant("task-1", intent, "policy-v1")
    tampered = _intent(parameters={"title": "safe", "body": "tampered"})
    with pytest.raises(CapabilityGrantError, match="intent_hash_mismatch"):
        consume_capability_grant(grant, tampered)


def test_evidence_tampering_is_rejected():
    intent = _intent()
    grant = issue_capability_grant("task-1", intent, "policy-v1", ["ev-1"])
    with pytest.raises(CapabilityGrantError, match="evidence_hash_mismatch"):
        consume_capability_grant(grant, intent, ["ev-2"])


def test_expired_grant_is_rejected():
    intent = _intent()
    grant = issue_capability_grant("task-1", intent, "policy-v1", ttl_seconds=1)
    future = datetime.now(timezone.utc) + timedelta(seconds=2)
    with pytest.raises(CapabilityGrantError, match="grant_expired"):
        consume_capability_grant(grant, intent, now=future)


def test_non_positive_ttl_is_rejected():
    with pytest.raises(CapabilityGrantError, match="invalid_ttl"):
        issue_capability_grant("task-1", _intent(), "policy-v1", ttl_seconds=0)

def test_outcome_contract_is_bound_to_grant():
    intent = _intent(action="delete", resource="staging_filesystem", irreversible=True, requires_filesystem=True)
    intent.parameters = {"outcome_contract": {"type": "state_match", "verifier": "filesystem_independent_v1", "expected_state": "ABSENT"}}
    grant = issue_capability_grant(
        "task-contract",
        intent,
        "policy-v1",
        outcome_contract={"type": "state_match", "verifier": "filesystem_independent_v1", "expected_state": "ABSENT"},
    )
    assert grant.to_dict()["outcome_contract"]["type"] == "state_match"
    assert grant.verify_binding(intent, []) is True


def test_outcome_contract_mismatch_blocks_consumption():
    intent = _intent(action="delete", resource="staging_filesystem", irreversible=True, requires_filesystem=True)
    intent.parameters = {"outcome_contract": {"type": "state_match", "verifier": "filesystem_independent_v1", "expected_state": "ABSENT"}}
    with pytest.raises(CapabilityGrantError, match="outcome_contract_mismatch"):
        issue_capability_grant(
            "task-contract-mismatch",
            intent,
            "policy-v1",
            outcome_contract={"type": "state_match", "verifier": "filesystem_independent_v1", "expected_state": "PRESENT"},
        )
