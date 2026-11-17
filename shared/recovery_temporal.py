import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from shared.recovery_evidence import RecoveryEvidenceChain
from shared.recovery_trust import RecoveryAttestorRegistry, RecoveryAttestorStatus, RecoveryTrustError


SCHEMA_VERSION = "recovery-temporal-proof-v1"
ALGORITHM = "Ed25519"


class TemporalTrustError(ValueError):
    pass


def canonical_json(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def trust_event_id(key_id, event):
    if not isinstance(key_id, str) or not key_id:
        raise TemporalTrustError("trust_key_id_required")
    if not isinstance(event, dict):
        raise TemporalTrustError("trust_event_required")
    required = ("from_status", "to_status", "occurred_at", "reason")
    for field in required:
        if field not in event:
            raise TemporalTrustError(f"trust_event_field_missing:{field}")
    payload = {
        "key_id": key_id,
        "from_status": event["from_status"],
        "to_status": event["to_status"],
        "occurred_at": event["occurred_at"],
        "reason": event["reason"],
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _decode(value, field):
    try:
        return base64.urlsafe_b64decode(str(value).encode("ascii"))
    except Exception as exc:
        raise TemporalTrustError(f"invalid_base64:{field}") from exc


def current_trust_context(registry, key_id):
    if not isinstance(registry, RecoveryAttestorRegistry):
        raise TemporalTrustError("attestor_registry_required")
    attestor = registry.get(key_id)
    if attestor is None:
        raise TemporalTrustError("untrusted_attestor")
    if registry.status(key_id) != RecoveryAttestorStatus.ACTIVE:
        raise TemporalTrustError("attestor_not_active")
    history = registry.history(key_id)
    if not history:
        raise TemporalTrustError("trust_history_missing")
    event = history[-1]
    if event["to_status"] != RecoveryAttestorStatus.ACTIVE:
        raise TemporalTrustError("active_trust_event_missing")
    return {
        "key_id": key_id,
        "public_key": attestor.public_key,
        "status": RecoveryAttestorStatus.ACTIVE,
        "event_id": trust_event_id(key_id, event),
        "event": dict(event),
    }


def _integrity_payload(proof):
    return {
        "schema_version": proof["schema_version"],
        "algorithm": proof["algorithm"],
        "key_id": proof["key_id"],
        "public_key": proof["public_key"],
        "trust_event_id": proof["trust_event_id"],
        "trust_event": proof["trust_event"],
        "recovery_artifact": proof["recovery_artifact"],
    }


def _signature_payload(proof):
    return {
        **_integrity_payload(proof),
        "proof_id": proof["proof_id"],
    }


def _validate_shape(proof):
    if not isinstance(proof, dict):
        raise TemporalTrustError("proof_object_required")
    required = (
        "schema_version",
        "algorithm",
        "key_id",
        "public_key",
        "trust_event_id",
        "trust_event",
        "proof_id",
        "recovery_artifact",
        "signature",
    )
    for field in required:
        if field not in proof:
            raise TemporalTrustError(f"proof_field_missing:{field}")
    if proof["schema_version"] != SCHEMA_VERSION:
        raise TemporalTrustError("unsupported_proof_schema")
    if proof["algorithm"] != ALGORITHM:
        raise TemporalTrustError("unsupported_proof_algorithm")
    if not isinstance(proof["trust_event"], dict):
        raise TemporalTrustError("trust_event_required")
    expected_event_id = trust_event_id(proof["key_id"], proof["trust_event"])
    if proof["trust_event_id"] != expected_event_id:
        raise TemporalTrustError("trust_event_id_mismatch")
    if not isinstance(proof["recovery_artifact"], dict):
        raise TemporalTrustError("recovery_artifact_required")
    result = RecoveryEvidenceChain.verify_artifact(proof["recovery_artifact"])
    if not result["valid"]:
        raise TemporalTrustError(f"recovery_artifact_invalid:{result['error']}")


def sign_temporal_recovery_proof(recovery_artifact, signer, trusted_attestors):
    if not isinstance(recovery_artifact, dict):
        raise TemporalTrustError("recovery_artifact_required")
    result = RecoveryEvidenceChain.verify_artifact(recovery_artifact)
    if not result["valid"]:
        raise TemporalTrustError(f"recovery_artifact_invalid:{result['error']}")
    if not all(hasattr(signer, attr) for attr in ("sign_payload", "key_id", "public_key")):
        raise TemporalTrustError("signer_payload_api_required")

    context = current_trust_context(trusted_attestors, signer.key_id)
    if context["public_key"] != signer.public_key:
        raise TemporalTrustError("attestor_key_mismatch")

    proof = {
        "schema_version": SCHEMA_VERSION,
        "algorithm": ALGORITHM,
        "key_id": signer.key_id,
        "public_key": signer.public_key,
        "trust_event_id": context["event_id"],
        "trust_event": context["event"],
        "proof_id": "",
        "recovery_artifact": recovery_artifact,
    }
    proof["proof_id"] = hashlib.sha256(
        canonical_json(_integrity_payload(proof)).encode("utf-8")
    ).hexdigest()
    signature = signer.sign_payload(_signature_payload(proof))
    proof["signature"] = base64.urlsafe_b64encode(signature).decode("ascii")
    return proof


def verify_temporal_recovery_proof(proof, trusted_attestors=None):
    _validate_shape(proof)

    expected_id = hashlib.sha256(
        canonical_json(_integrity_payload(proof)).encode("utf-8")
    ).hexdigest()
    if proof["proof_id"] != expected_id:
        raise TemporalTrustError("proof_id_mismatch")

    public_raw = _decode(proof["public_key"], "public_key")
    if len(public_raw) != 32:
        raise TemporalTrustError("invalid_ed25519_public_key")
    expected_key_id = "ed25519-" + hashlib.sha256(public_raw).hexdigest()[:16]
    if proof["key_id"] != expected_key_id:
        raise TemporalTrustError("key_id_public_key_mismatch")

    signature = _decode(proof["signature"], "signature")
    if len(signature) != 64:
        raise TemporalTrustError("invalid_ed25519_signature")
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            signature,
            canonical_json(_signature_payload(proof)).encode("utf-8"),
        )
    except Exception as exc:
        raise TemporalTrustError("proof_signature_invalid") from exc

    if trusted_attestors is not None:
        if not isinstance(trusted_attestors, RecoveryAttestorRegistry):
            raise TemporalTrustError("attestor_registry_required")
        attestor = trusted_attestors.get(proof["key_id"])
        if attestor is None:
            raise TemporalTrustError("untrusted_attestor")
        if attestor.public_key != proof["public_key"]:
            raise TemporalTrustError("attestor_key_mismatch")

        matched = False
        for event in trusted_attestors.history(proof["key_id"]):
            if (
                event["to_status"] == RecoveryAttestorStatus.ACTIVE
                and trust_event_id(proof["key_id"], event) == proof["trust_event_id"]
                and event == proof["trust_event"]
            ):
                matched = True
                break
        if not matched:
            raise TemporalTrustError("historical_trust_event_not_found")

    artifact = proof["recovery_artifact"]
    result = RecoveryEvidenceChain.verify_artifact(artifact)
    return {
        "valid": True,
        "proof_id": proof["proof_id"],
        "key_id": proof["key_id"],
        "algorithm": proof["algorithm"],
        "trust_event_id": proof["trust_event_id"],
        "trust_status": proof["trust_event"]["to_status"],
        "recovery_id": artifact["recovery_id"],
        "attempt_id": artifact.get("attempt_id"),
        "events": result["events"],
        "head_hash": result["head_hash"],
    }
