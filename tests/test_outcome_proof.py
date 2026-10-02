import json

import pytest

from shared.capability_signing import CapabilitySigner
from shared.capability_grant import CapabilityGrant, evidence_hash
from shared.evidence_manifest import build_manifest, digest
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
        "agent_id": "test-agent",
        "authority_epoch": 1,
        "authority_state": "STANDARD",
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
        "agent_id": "test-agent",
        "authority_epoch": 1,
        "authority_state": "STANDARD",
        "intent_hash": "intent-hash",
        "policy_version": "capability-policy-v1",
        "executor_id": "staging_deploy",
        "executor_version": "1",
        "status": "EXECUTED",
    }
    contract = grant["outcome_contract"]
    outcome = {
        "agent_id": "test-agent",
        "status": "PROVEN",
        "verifier": "artifact_independent_v1",
        "outcome_id": "outcome-1",
    }
    evidence = {
        "agent_id": "test-agent",
        "outcome_id": "outcome-1",
        "evidence_id": "evidence-1",
        "verifier": "artifact_independent_v1",
        "status": "PROVEN",
        "source": "evidence-ledger",
        "executor_id": "staging_deploy",
        "executor_version": "1",
    }
    signed_grant = signer.sign(CapabilityGrant.from_dict(grant)).to_dict()
    manifest = build_manifest([
        {"id": "grant", "type": "capability_grant", "digest": digest(signed_grant)},
        {"id": "receipt", "type": "execution_receipt", "digest": digest(receipt)},
        {"id": "contract", "type": "outcome_contract", "digest": digest(contract)},
        {"id": "outcome", "type": "verified_outcome", "digest": digest(outcome)},
        {"id": "evidence", "type": "outcome_evidence", "digest": digest(evidence)},
    ], agent_id="test-agent")
    payload = build_outcome_proof_payload(signed_grant, receipt, contract, outcome, evidence, manifest)
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


def test_builder_rejects_cross_agent_outcome():
    proof = _proof()
    outcome = dict(proof["outcome"])
    outcome["agent_id"] = "other-agent"
    with pytest.raises(OutcomeProofError, match="outcome_agent_mismatch"):
        build_outcome_proof_payload(
            proof["grant"], proof["receipt"], proof["outcome_contract"],
            outcome, proof["evidence"], proof["evidence_manifest"],
        )


def test_builder_rejects_cross_agent_evidence():
    proof = _proof()
    evidence = dict(proof["evidence"])
    evidence["agent_id"] = "other-agent"
    with pytest.raises(OutcomeProofError, match="evidence_agent_mismatch"):
        build_outcome_proof_payload(
            proof["grant"], proof["receipt"], proof["outcome_contract"],
            proof["outcome"], evidence, proof["evidence_manifest"],
        )


def test_builder_rejects_cross_agent_manifest():
    proof = _proof()
    manifest = dict(proof["evidence_manifest"])
    manifest["agent_id"] = "other-agent"
    with pytest.raises(OutcomeProofError, match="manifest_agent_mismatch"):
        build_outcome_proof_payload(
            proof["grant"], proof["receipt"], proof["outcome_contract"],
            proof["outcome"], proof["evidence"], manifest,
        )


def test_builder_rejects_missing_executor_identity():
    proof = _proof()
    receipt = dict(proof["receipt"])
    receipt.pop("executor_id")
    with pytest.raises(OutcomeProofError, match="executor_identity_required"):
        build_outcome_proof_payload(
            proof["grant"],
            receipt,
            proof["outcome_contract"],
            proof["outcome"],
            proof["evidence"],
            proof["evidence_manifest"],
        )


def test_builder_rejects_executor_evidence_mismatch():
    proof = _proof()
    evidence = dict(proof["evidence"])
    evidence["executor_id"] = "other-executor"
    with pytest.raises(OutcomeProofError, match="evidence_executor_mismatch"):
        build_outcome_proof_payload(
            proof["grant"],
            proof["receipt"],
            proof["outcome_contract"],
            proof["outcome"],
            evidence,
            proof["evidence_manifest"],
        )


def test_verifier_rejects_tampered_executor_identity():
    proof = _proof()
    proof["receipt"]["executor_id"] = "other-executor"
    with pytest.raises(OutcomeProofError, match="proof_id_mismatch|proof_signature_invalid"):
        verify_outcome_proof(proof)
