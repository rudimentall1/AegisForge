from datetime import datetime, timedelta, timezone
import base64
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared.attestor_registry import AttestorError, AttestorRecord, attest_outcome, create_registry, verify_attestation, verify_registry

def _record(key, status="ACTIVE", start=None, end=None):
    now = start or datetime.now(timezone.utc)
    end = end or (now + timedelta(days=30))
    public = base64.urlsafe_b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")
    return AttestorRecord("attestor-1", "attestor-key-1", public, ("artifact_independent_v1",), status, now.isoformat(), end.isoformat())

def test_signed_registry_and_attestation_verify():
    issuer = Ed25519PrivateKey.generate()
    key = Ed25519PrivateKey.generate()
    registry = create_registry([_record(key)], issuer)
    assert verify_registry(registry.to_dict())["valid"]
    proof = {"proof_id": "proof-123"}
    attestation = attest_outcome(proof, key, "attestor-1", "attestor-key-1", "artifact_independent_v1")
    assert verify_attestation(attestation, proof, registry.to_dict())["valid"]

def test_unknown_attestor_rejected():
    registry = create_registry([], Ed25519PrivateKey.generate()).to_dict()
    with pytest.raises(AttestorError, match="attestor_not_found"):
        verify_attestation(attest_outcome({"proof_id": "p"}, Ed25519PrivateKey.generate(), "missing", "k", "artifact_independent_v1"), {"proof_id": "p"}, registry)

def test_revoked_attestor_rejected():
    key = Ed25519PrivateKey.generate()
    registry = create_registry([_record(key, status="REVOKED")], Ed25519PrivateKey.generate()).to_dict()
    attestation = attest_outcome({"proof_id": "p"}, key, "attestor-1", "attestor-key-1", "artifact_independent_v1")
    with pytest.raises(AttestorError, match="attestor_not_active"):
        verify_attestation(attestation, {"proof_id": "p"}, registry)

def test_verifier_scope_rejected():
    key = Ed25519PrivateKey.generate()
    registry = create_registry([_record(key)], Ed25519PrivateKey.generate()).to_dict()
    attestation = attest_outcome({"proof_id": "p"}, key, "attestor-1", "attestor-key-1", "other_verifier")
    with pytest.raises(AttestorError, match="verifier_not_authorized_for_attestor"):
        verify_attestation(attestation, {"proof_id": "p"}, registry)

def test_proof_binding_rejected():
    key = Ed25519PrivateKey.generate()
    registry = create_registry([_record(key)], Ed25519PrivateKey.generate()).to_dict()
    attestation = attest_outcome({"proof_id": "p1"}, key, "attestor-1", "attestor-key-1", "artifact_independent_v1")
    with pytest.raises(AttestorError, match="attestation_proof_mismatch"):
        verify_attestation(attestation, {"proof_id": "p2"}, registry)

def test_registry_tampering_rejected():
    key = Ed25519PrivateKey.generate()
    registry = create_registry([_record(key)], Ed25519PrivateKey.generate()).to_dict()
    registry["attestors"][0]["status"] = "REVOKED"
    with pytest.raises(AttestorError, match="registry_signature_invalid"):
        verify_registry(registry)

def test_expired_attestor_rejected():
    key = Ed25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    registry = create_registry([_record(key, start=now-timedelta(days=2), end=now-timedelta(days=1))], Ed25519PrivateKey.generate()).to_dict()
    attestation = attest_outcome({"proof_id": "p"}, key, "attestor-1", "attestor-key-1", "artifact_independent_v1")
    with pytest.raises(AttestorError, match="attestor_not_active"):
        verify_attestation(attestation, {"proof_id": "p"}, registry)
