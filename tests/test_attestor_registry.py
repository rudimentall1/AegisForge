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

def _issuer_trust(registry):
    return {registry["issuer_key_id"]: base64.urlsafe_b64decode(registry["issuer_public_key"].encode("ascii"))}


def test_signed_registry_and_attestation_verify():
    issuer = Ed25519PrivateKey.generate()
    key = Ed25519PrivateKey.generate()
    registry = create_registry([_record(key)], issuer)
    assert verify_registry(registry.to_dict(), trusted_issuer_public_keys=_issuer_trust(registry.to_dict()))["valid"]
    proof = {"proof_id": "proof-123"}
    attestation = attest_outcome(proof, key, "attestor-1", "attestor-key-1", "artifact_independent_v1")
    assert verify_attestation(attestation, proof, registry.to_dict(), trusted_issuer_public_keys=_issuer_trust(registry.to_dict()))["valid"]

def test_unknown_attestor_rejected():
    registry = create_registry([], Ed25519PrivateKey.generate()).to_dict()
    with pytest.raises(AttestorError, match="attestor_not_found"):
        verify_attestation(attest_outcome({"proof_id": "p"}, Ed25519PrivateKey.generate(), "missing", "k", "artifact_independent_v1"), {"proof_id": "p"}, registry, trusted_issuer_public_keys=_issuer_trust(registry))

def test_revoked_attestor_rejected():
    key = Ed25519PrivateKey.generate()
    registry = create_registry([_record(key, status="REVOKED")], Ed25519PrivateKey.generate()).to_dict()
    attestation = attest_outcome({"proof_id": "p"}, key, "attestor-1", "attestor-key-1", "artifact_independent_v1")
    with pytest.raises(AttestorError, match="attestor_not_active"):
        verify_attestation(attestation, {"proof_id": "p"}, registry, trusted_issuer_public_keys=_issuer_trust(registry))

def test_verifier_scope_rejected():
    key = Ed25519PrivateKey.generate()
    registry = create_registry([_record(key)], Ed25519PrivateKey.generate()).to_dict()
    attestation = attest_outcome({"proof_id": "p"}, key, "attestor-1", "attestor-key-1", "other_verifier")
    with pytest.raises(AttestorError, match="verifier_not_authorized_for_attestor"):
        verify_attestation(attestation, {"proof_id": "p"}, registry, trusted_issuer_public_keys=_issuer_trust(registry))

def test_proof_binding_rejected():
    key = Ed25519PrivateKey.generate()
    registry = create_registry([_record(key)], Ed25519PrivateKey.generate()).to_dict()
    attestation = attest_outcome({"proof_id": "p1"}, key, "attestor-1", "attestor-key-1", "artifact_independent_v1")
    with pytest.raises(AttestorError, match="attestation_proof_mismatch"):
        verify_attestation(attestation, {"proof_id": "p2"}, registry, trusted_issuer_public_keys=_issuer_trust(registry))

def test_registry_tampering_rejected():
    key = Ed25519PrivateKey.generate()
    registry = create_registry([_record(key)], Ed25519PrivateKey.generate()).to_dict()
    registry["attestors"][0]["status"] = "REVOKED"
    with pytest.raises(AttestorError, match="registry_signature_invalid"):
        verify_registry(registry, trusted_issuer_public_keys=_issuer_trust(registry))

def test_expired_attestor_rejected():
    key = Ed25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    registry = create_registry([_record(key, start=now-timedelta(days=2), end=now-timedelta(days=1))], Ed25519PrivateKey.generate()).to_dict()
    attestation = attest_outcome({"proof_id": "p"}, key, "attestor-1", "attestor-key-1", "artifact_independent_v1")
    with pytest.raises(AttestorError, match="attestor_not_active"):
        verify_attestation(attestation, {"proof_id": "p"}, registry, trusted_issuer_public_keys=_issuer_trust(registry))


def test_registry_rejects_unsigned_extension_fields():
    registry = create_registry([], Ed25519PrivateKey.generate()).to_dict()
    registry["claimed_independence"] = True
    with pytest.raises(AttestorError, match="invalid_registry_fields"):
        verify_registry(registry, trusted_issuer_public_keys=_issuer_trust(registry))


def test_registry_rejects_issuer_key_id_substitution():
    registry = create_registry([], Ed25519PrivateKey.generate()).to_dict()
    registry["issuer_key_id"] = "registry-attacker-controlled"
    with pytest.raises(AttestorError, match="registry_issuer_key_id_mismatch"):
        verify_registry(registry, trusted_issuer_public_keys=_issuer_trust(registry))


def test_registry_rejects_malformed_base64_in_issuer_key():
    registry = create_registry([], Ed25519PrivateKey.generate()).to_dict()
    registry["issuer_public_key"] += "!"
    with pytest.raises(AttestorError, match="invalid_base64:issuer_public_key"):
        verify_registry(registry, trusted_issuer_public_keys=_issuer_trust(registry))


def test_registry_rejects_naive_timestamps():
    key = Ed25519PrivateKey.generate()
    record = _record(key).to_dict()
    record["valid_from"] = "2026-01-01T00:00:00"
    with pytest.raises(AttestorError, match="invalid_timestamp:valid_from"):
        create_registry([record], Ed25519PrivateKey.generate())


def test_attestation_rejects_unsigned_extension_fields():
    key = Ed25519PrivateKey.generate()
    registry = create_registry([_record(key)], Ed25519PrivateKey.generate()).to_dict()
    proof = {"proof_id": "proof-123"}
    attestation = attest_outcome(proof, key, "attestor-1", "attestor-key-1", "artifact_independent_v1")
    attestation["runner_measurement"] = "unbound-claim"
    with pytest.raises(AttestorError, match="invalid_attestation_fields"):
        verify_attestation(attestation, proof, registry, trusted_issuer_public_keys=_issuer_trust(registry))


def test_attestation_rejects_malformed_signature_encoding():
    key = Ed25519PrivateKey.generate()
    registry = create_registry([_record(key)], Ed25519PrivateKey.generate()).to_dict()
    proof = {"proof_id": "proof-123"}
    attestation = attest_outcome(proof, key, "attestor-1", "attestor-key-1", "artifact_independent_v1")
    attestation["signature"] += "!"
    with pytest.raises(AttestorError, match="attestation_signature_invalid"):
        verify_attestation(attestation, proof, registry, trusted_issuer_public_keys=_issuer_trust(registry))


def test_self_signed_registry_is_not_trusted_without_out_of_band_anchor():
    registry = create_registry([], Ed25519PrivateKey.generate()).to_dict()
    with pytest.raises(AttestorError, match="registry_issuer_trust_anchor_required"):
        verify_registry(registry)


def test_registry_rejected_when_pinned_issuer_key_differs():
    registry = create_registry([], Ed25519PrivateKey.generate()).to_dict()
    other_key = Ed25519PrivateKey.generate()
    other_public = other_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    with pytest.raises(AttestorError, match="registry_issuer_not_trusted"):
        verify_registry(registry, trusted_issuer_public_keys={registry["issuer_key_id"]: other_public})
