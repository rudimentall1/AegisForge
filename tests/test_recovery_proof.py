import base64
import sqlite3

import pytest

from shared.capability_signing import CapabilitySigner
from shared.recovery_evidence import RecoveryEvidenceChain
from shared.recovery_proof import (
    RecoveryProofError,
    sign_recovery_proof,
    verify_recovery_proof,
)


def make_artifact():
    db = sqlite3.connect(":memory:")
    chain = RecoveryEvidenceChain(db)
    chain.append("recovery-1", "attempt-1", "RECOVERY_OPENED", {"reason": "stale"})
    chain.append("recovery-1", "attempt-1", "VERIFICATION_DECISION", {"decision": "SAFE_TO_RETRY"})
    return chain.export_artifact("recovery-1")


def test_recovery_proof_round_trip_and_offline_verification():
    artifact = make_artifact()
    signer = CapabilitySigner.generate(key_id="recovery-ed25519-test")

    # CapabilitySigner supports caller-selected key IDs; the proof verifier
    # intentionally derives and validates the canonical public-key identity.
    signer = CapabilitySigner.generate()
    proof = sign_recovery_proof(artifact, signer)

    result = verify_recovery_proof(proof)

    assert result["valid"] is True
    assert result["recovery_id"] == "recovery-1"
    assert result["attempt_id"] == "attempt-1"
    assert result["events"] == 2
    assert result["head_hash"] == artifact["head_hash"]


def test_recovery_proof_rejects_event_tampering():
    proof = sign_recovery_proof(make_artifact(), CapabilitySigner.generate())
    proof["recovery_artifact"]["events"][0]["payload"]["reason"] = "tampered"

    with pytest.raises(RecoveryProofError, match="recovery_artifact_invalid:event_hash_mismatch"):
        verify_recovery_proof(proof)


def test_recovery_proof_rejects_signature_tampering():
    proof = sign_recovery_proof(make_artifact(), CapabilitySigner.generate())
    raw = bytearray(base64.urlsafe_b64decode(proof["signature"].encode("ascii")))
    raw[0] ^= 1
    proof["signature"] = base64.urlsafe_b64encode(bytes(raw)).decode("ascii")

    with pytest.raises(RecoveryProofError, match="proof_signature_invalid"):
        verify_recovery_proof(proof)


def test_recovery_proof_rejects_public_key_substitution():
    proof = sign_recovery_proof(make_artifact(), CapabilitySigner.generate())
    proof["public_key"] = CapabilitySigner.generate().public_key

    with pytest.raises(RecoveryProofError, match="proof_id_mismatch"):
        verify_recovery_proof(proof)


def test_recovery_proof_rejects_invalid_artifact_before_signing():
    artifact = make_artifact()
    artifact["head_hash"] = "0" * 64

    with pytest.raises(RecoveryProofError, match="recovery_artifact_invalid:head_hash_mismatch"):
        sign_recovery_proof(artifact, CapabilitySigner.generate())
