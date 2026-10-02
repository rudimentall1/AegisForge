import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

SCHEMA_VERSION = "attestor-registry-v1"
ATTESTATION_SCHEMA = "outcome-attestation-v1"
ALGORITHM = "Ed25519"

class AttestorError(ValueError):
    pass

def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

def _b64(value, field):
    try:
        return base64.urlsafe_b64decode(str(value).encode("ascii"))
    except Exception as exc:
        raise AttestorError(f"invalid_base64:{field}") from exc

def _public_key(private_key):
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).decode("ascii")

def _parse_time(value, field):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception as exc:
        raise AttestorError(f"invalid_timestamp:{field}") from exc

def _active(record, now=None):
    if record["status"] != "ACTIVE":
        return False
    current = now or datetime.now(timezone.utc)
    return _parse_time(record["valid_from"], "valid_from") <= current < _parse_time(record["expires_at"], "expires_at")

@dataclass(frozen=True)
class AttestorRecord:
    attestor_id: str
    key_id: str
    public_key: str
    allowed_verifiers: tuple
    status: str = "ACTIVE"
    valid_from: str = ""
    expires_at: str = ""

    def to_dict(self):
        return {
            "attestor_id": self.attestor_id,
            "key_id": self.key_id,
            "public_key": self.public_key,
            "allowed_verifiers": list(self.allowed_verifiers),
            "status": self.status,
            "valid_from": self.valid_from,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, payload):
        if not isinstance(payload, dict):
            raise AttestorError("attestor_record_required")
        required = {"attestor_id", "key_id", "public_key", "allowed_verifiers", "status", "valid_from", "expires_at"}
        missing = sorted(required - set(payload))
        if missing:
            raise AttestorError("attestor_fields_missing:" + ",".join(missing))
        allowed = payload["allowed_verifiers"]
        if not isinstance(allowed, list) or not all(isinstance(v, str) and v for v in allowed):
            raise AttestorError("invalid_allowed_verifiers")
        public = _b64(payload["public_key"], "public_key")
        if len(public) != 32:
            raise AttestorError("invalid_ed25519_public_key")
        if payload["status"] not in {"ACTIVE", "SUSPENDED", "REVOKED"}:
            raise AttestorError("invalid_attestor_status")
        start = _parse_time(payload["valid_from"], "valid_from")
        end = _parse_time(payload["expires_at"], "expires_at")
        if start >= end:
            raise AttestorError("invalid_attestor_validity")
        return cls(
            attestor_id=str(payload["attestor_id"]),
            key_id=str(payload["key_id"]),
            public_key=str(payload["public_key"]),
            allowed_verifiers=tuple(sorted(set(allowed))),
            status=str(payload["status"]),
            valid_from=str(payload["valid_from"]),
            expires_at=str(payload["expires_at"]),
        )

@dataclass(frozen=True)
class SignedAttestorRegistry:
    registry_id: str
    issuer_key_id: str
    issuer_public_key: str
    attestors: tuple
    signature: str
    algorithm: str = ALGORITHM

    def unsigned_payload(self):
        return {
            "schema_version": SCHEMA_VERSION,
            "algorithm": self.algorithm,
            "registry_id": self.registry_id,
            "issuer_key_id": self.issuer_key_id,
            "issuer_public_key": self.issuer_public_key,
            "attestors": [a.to_dict() for a in self.attestors],
        }

    def to_dict(self):
        payload = self.unsigned_payload()
        payload["signature"] = self.signature
        return payload

def create_registry(records, issuer_private_key, registry_id="aegisforge-root"):
    if not isinstance(issuer_private_key, Ed25519PrivateKey):
        raise AttestorError("issuer_private_key_required")
    normalized = tuple(sorted(
        (AttestorRecord.from_dict(r) if isinstance(r, dict) else r for r in records),
        key=lambda x: x.attestor_id,
    ))
    if len({a.attestor_id for a in normalized}) != len(normalized):
        raise AttestorError("duplicate_attestor_id")
    issuer_public = _public_key(issuer_private_key)
    issuer_key_id = "registry-" + hashlib.sha256(_b64(issuer_public, "issuer_public_key")).hexdigest()[:16]
    payload = {
        "schema_version": SCHEMA_VERSION,
        "algorithm": ALGORITHM,
        "registry_id": str(registry_id),
        "issuer_key_id": issuer_key_id,
        "issuer_public_key": issuer_public,
        "attestors": [a.to_dict() for a in normalized],
    }
    signature = base64.urlsafe_b64encode(
        issuer_private_key.sign(canonical_json(payload).encode("utf-8"))
    ).decode("ascii")
    return SignedAttestorRegistry(
        registry_id=str(registry_id),
        issuer_key_id=issuer_key_id,
        issuer_public_key=issuer_public,
        attestors=normalized,
        signature=signature,
    )

def verify_registry(registry):
    if not isinstance(registry, dict):
        raise AttestorError("registry_required")
    required = {"schema_version", "algorithm", "registry_id", "issuer_key_id", "issuer_public_key", "attestors", "signature"}
    missing = sorted(required - set(registry))
    if missing:
        raise AttestorError("registry_fields_missing:" + ",".join(missing))
    if registry["schema_version"] != SCHEMA_VERSION or registry["algorithm"] != ALGORITHM:
        raise AttestorError("unsupported_registry_schema_or_algorithm")
    issuer = _b64(registry["issuer_public_key"], "issuer_public_key")
    if len(issuer) != 32:
        raise AttestorError("invalid_registry_public_key")
    records = [AttestorRecord.from_dict(r) for r in registry["attestors"]]
    if len({a.attestor_id for a in records}) != len(records):
        raise AttestorError("duplicate_attestor_id")
    payload = {k: registry[k] for k in ("schema_version", "algorithm", "registry_id", "issuer_key_id", "issuer_public_key", "attestors")}
    try:
        Ed25519PublicKey.from_public_bytes(issuer).verify(
            _b64(registry["signature"], "signature"),
            canonical_json(payload).encode("utf-8"),
        )
    except Exception as exc:
        raise AttestorError("registry_signature_invalid") from exc
    return {"valid": True, "registry_id": registry["registry_id"], "attestor_count": len(records)}

def resolve_attestor(registry, attestor_id, verifier, now=None):
    verify_registry(registry)
    for raw in registry["attestors"]:
        record = AttestorRecord.from_dict(raw)
        if record.attestor_id != attestor_id:
            continue
        if not _active(record.to_dict(), now):
            raise AttestorError("attestor_not_active")
        if verifier not in record.allowed_verifiers:
            raise AttestorError("verifier_not_authorized_for_attestor")
        return record
    raise AttestorError("attestor_not_found")

def attest_outcome(proof, attestor_private_key, attestor_id, key_id, verifier, now=None):
    if not isinstance(proof, dict) or not proof.get("proof_id"):
        raise AttestorError("proof_required")
    if not isinstance(attestor_private_key, Ed25519PrivateKey):
        raise AttestorError("attestor_private_key_required")
    if not verifier:
        raise AttestorError("verifier_required")
    issued_at = (now or datetime.now(timezone.utc)).isoformat()
    payload = {
        "schema_version": ATTESTATION_SCHEMA,
        "algorithm": ALGORITHM,
        "attestor_id": str(attestor_id),
        "key_id": str(key_id),
        "proof_id": str(proof["proof_id"]),
        "verifier": str(verifier),
        "issued_at": issued_at,
    }
    payload["signature"] = base64.urlsafe_b64encode(
        attestor_private_key.sign(canonical_json(payload).encode("utf-8"))
    ).decode("ascii")
    return payload

def verify_attestation(attestation, proof, registry, now=None):
    if not isinstance(attestation, dict) or not isinstance(proof, dict):
        raise AttestorError("attestation_and_proof_required")
    required = {"schema_version", "algorithm", "attestor_id", "key_id", "proof_id", "verifier", "issued_at", "signature"}
    missing = sorted(required - set(attestation))
    if missing:
        raise AttestorError("attestation_fields_missing:" + ",".join(missing))
    if attestation["schema_version"] != ATTESTATION_SCHEMA or attestation["algorithm"] != ALGORITHM:
        raise AttestorError("unsupported_attestation_schema_or_algorithm")
    if attestation["proof_id"] != proof.get("proof_id"):
        raise AttestorError("attestation_proof_mismatch")
    record = resolve_attestor(registry, attestation["attestor_id"], attestation["verifier"], now=now)
    if record.key_id != attestation["key_id"]:
        raise AttestorError("attestor_key_id_mismatch")
    issued = _parse_time(attestation["issued_at"], "issued_at")
    if issued < _parse_time(record.valid_from, "valid_from") or issued >= _parse_time(record.expires_at, "expires_at"):
        raise AttestorError("attestation_outside_attestor_validity")
    payload = {k: attestation[k] for k in ("schema_version", "algorithm", "attestor_id", "key_id", "proof_id", "verifier", "issued_at")}
    try:
        Ed25519PublicKey.from_public_bytes(_b64(record.public_key, "public_key")).verify(
            _b64(attestation["signature"], "signature"),
            canonical_json(payload).encode("utf-8"),
        )
    except Exception as exc:
        raise AttestorError("attestation_signature_invalid") from exc
    return {
        "valid": True,
        "attestor_id": record.attestor_id,
        "key_id": record.key_id,
        "proof_id": proof["proof_id"],
        "verifier": attestation["verifier"],
        "registry_id": registry["registry_id"],
    }
