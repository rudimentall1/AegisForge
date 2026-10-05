import sqlite3

import pytest

from shared.capability_signing import CapabilitySigner
from shared.recovery_evidence import RecoveryEvidenceChain
from shared.recovery_trust import (
    RecoveryAttestor,
    RecoveryAttestorRegistry,
    RecoveryAttestorStatus,
)
from shared.recovery_temporal import (
    TemporalTrustError,
    sign_temporal_recovery_proof,
    trust_event_id,
    verify_temporal_recovery_proof,
)


def make_artifact():
    db = sqlite3.connect(":memory:")
    chain = RecoveryEvidenceChain(db)
    chain.append("recovery-1", "attempt-1", "RECOVERY_OPENED", {"reason": "stale"})
    chain.append(
        "recovery-1",
        "attempt-1",
        "VERIFICATION_DECISION",
        {"decision": "SAFE_TO_RETRY"},
    )
    return chain.export_artifact("recovery-1")


def make_attestor():
    signer = CapabilitySigner.generate()
    attestor = RecoveryAttestor(
        key_id=signer.key_id,
        public_key=signer.public_key,
        name="temporal-test",
    )
    return signer, attestor


def test_temporal_proof_binds_to_active_trust_event():
    signer, attestor = make_attestor()
    registry = RecoveryAttestorRegistry([attestor])
    proof = sign_temporal_recovery_proof(make_artifact(), signer, registry)

    result = verify_temporal_recovery_proof(proof, trusted_attestors=registry)

    assert result["valid"] is True
    assert result["trust_status"] == RecoveryAttestorStatus.ACTIVE
    assert result["trust_event_id"] == trust_event_id(
        signer.key_id, registry.history(signer.key_id)[0]
    )


def test_temporal_proof_remains_historically_valid_after_revocation():
    signer, attestor = make_attestor()
    registry = RecoveryAttestorRegistry([attestor])
    proof = sign_temporal_recovery_proof(make_artifact(), signer, registry)

    registry.transition(
        signer.key_id,
        RecoveryAttestorStatus.REVOKED,
        "key compromised after proof issuance",
    )

    result = verify_temporal_recovery_proof(proof, trusted_attestors=registry)
    assert result["valid"] is True


def test_temporal_proof_rejects_unknown_historical_event():
    signer, attestor = make_attestor()
    registry = RecoveryAttestorRegistry([attestor])
    proof = sign_temporal_recovery_proof(make_artifact(), signer, registry)

    registry._history[signer.key_id][0]["reason"] = "tampered"

    with pytest.raises(TemporalTrustError, match="historical_trust_event_not_found"):
        verify_temporal_recovery_proof(proof, trusted_attestors=registry)


def test_temporal_proof_rejects_trust_event_tampering():
    signer, attestor = make_attestor()
    registry = RecoveryAttestorRegistry([attestor])
    proof = sign_temporal_recovery_proof(make_artifact(), signer, registry)
    proof["trust_event"]["reason"] = "tampered"

    with pytest.raises(TemporalTrustError, match="trust_event_id_mismatch"):
        verify_temporal_recovery_proof(proof)


def test_temporal_proof_survives_registry_restart(tmp_path):
    signer, attestor = make_attestor()
    db = tmp_path / "attestors.sqlite3"

    first = RecoveryAttestorRegistry([attestor], store=db)
    proof = sign_temporal_recovery_proof(make_artifact(), signer, first)

    restarted = RecoveryAttestorRegistry(store=db)
    result = verify_temporal_recovery_proof(proof, trusted_attestors=restarted)

    assert result["valid"] is True
    assert result["trust_event_id"] == trust_event_id(
        signer.key_id, restarted.history(signer.key_id)[0]
    )


def test_temporal_signing_requires_active_attestor():
    signer, attestor = make_attestor()
    registry = RecoveryAttestorRegistry([attestor])
    registry.transition(
        signer.key_id,
        RecoveryAttestorStatus.SUSPENDED,
        "maintenance",
    )

    with pytest.raises(TemporalTrustError, match="attestor_not_active"):
        sign_temporal_recovery_proof(make_artifact(), signer, registry)
