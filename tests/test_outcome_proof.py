import json

import pytest

from shared.capability_signing import CapabilitySigner
from shared.capability_grant import CapabilityGrant, evidence_hash
from shared.outcome_proof import (
    OutcomeProofError,
    build_outcome_proof_payload,
    sign_outcome_proof,
    verify_outcome_proof,
)


def _proof():
    signer = CapabilitySigner.generate(key_id="test-proof-key")
    grant = {
        "grant_id": "grant-1",
        "task_id": "task-1",
        "intent_hash": "intent-hash",
        "policy_version": "capability-policy-v1",
        "evidence_ids": ["e-1"],
        "evidence_hash": evidence_hash(["e-1"]),
        "authorized_action": "publish",
        "authorized_target": "staging",
        "authorized_scope": "artifact",
        "issued_at": "2026-10-02T00:00:00Z",
        "expires_at": "2026-10-02T01:00:00Z",
        "nonce": "nonce-1",
        "status": "ACTIVE",
        "outcome_contract": {
            "type": "artifact_exists",
            "verifier": "artifact_independent_v1",
            "path": "artifact.txt",
            "expected_exists": True,
        },
    }
    receipt = {
        "receipt_id": "receipt-1",
        "task_id": "task-1",
        "grant_id": "grant-1",
        "nonce": "nonce-1",
        "status": "EXECUTED",
    }
    contract = grant["outcome_contract"]
    outcome = {
        "status": "PROVEN",
        "verifier": "artifact_independent_v1",
        "outcome_id": "outcome-1",
    }
    evidence = {
        "outcome_id": "outcome-1",
        "evidence_id": "evidence-1",
        "verifier": "artifact_independent_v1",
        "status": "PROVEN",
        "source": "evidence-ledger",
    }
    signed_grant = signer.sign(CapabilityGrant.from_dict(grant)).to_dict()
    payload = build_outcome_proof_payload(signed_grant, receipt, contract, outcome, evidence)
    return sign_outcome_proof(payload, signer)


def test_signed_proof_verifies_offline():
    proof = _proof()
    result = verify_outcome_proof(proof)
    assert result["valid"] is True
    assert result["verifier"] == "artifact_independent_v1"


def test_tampered_proof_is_rejected():
    proof = _proof()
    proof["receipt"]["status"] = "FAILED"
    with pytest.raises(OutcomeProofError, match="proof_id_mismatch|proof_signature_invalid"):
        verify_outcome_proof(proof)


def test_contract_binding_is_required():
    proof = _proof()
    proof["outcome_contract"]["expected_exists"] = False
    with pytest.raises(OutcomeProofError, match="proof_id_mismatch|proof_signature_invalid|grant_contract_mismatch"):
        verify_outcome_proof(proof)
