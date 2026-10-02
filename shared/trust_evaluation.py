from dataclasses import dataclass
from datetime import datetime, timezone

from shared.attestor_registry import AttestorError, verify_attestation

SCHEMA_VERSION = "trust-evaluation-v1"

@dataclass(frozen=True)
class TrustDecision:
    status: str
    reason: str
    proof_id: str
    verifier: str
    attestor_id: str | None = None
    registry_id: str | None = None
    evaluated_at: str = ""

    def to_dict(self):
        return {
            "schema_version": SCHEMA_VERSION,
            "status": self.status,
            "reason": self.reason,
            "proof_id": self.proof_id,
            "verifier": self.verifier,
            "attestor_id": self.attestor_id,
            "registry_id": self.registry_id,
            "evaluated_at": self.evaluated_at,
        }


def evaluate_trust(proof, attestation, registry, now=None):
    now = now or datetime.now(timezone.utc)
    proof_id = proof.get("proof_id") if isinstance(proof, dict) else None
    verifier = ((proof or {}).get("outcome") or {}).get("verifier") if isinstance(proof, dict) else None
    if not proof_id or not verifier:
        return TrustDecision("UNTRUSTED", "proof_identity_incomplete", str(proof_id or ""), str(verifier or ""), evaluated_at=now.isoformat())
    if not isinstance(attestation, dict):
        return TrustDecision("UNTRUSTED", "attestation_missing", proof_id, verifier, evaluated_at=now.isoformat())
    if not isinstance(registry, dict):
        return TrustDecision("UNTRUSTED", "attestor_registry_missing", proof_id, verifier, evaluated_at=now.isoformat())
    try:
        result = verify_attestation(attestation, proof, registry, now=now)
    except AttestorError as exc:
        reason = str(exc)
        status = "EXPIRED" if reason in {"attestor_not_active", "attestation_outside_attestor_validity"} else "UNTRUSTED"
        if reason == "attestor_not_active":
            # Distinguish a temporal expiry from explicit suspension/revocation.
            try:
                records = registry.get("attestors", [])
                record = next(r for r in records if r.get("attestor_id") == attestation.get("attestor_id"))
                status = "EXPIRED" if now >= datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00")) else "UNTRUSTED"
            except Exception:
                status = "UNTRUSTED"
        return TrustDecision(status, reason, proof_id, verifier, attestor_id=attestation.get("attestor_id"), registry_id=registry.get("registry_id"), evaluated_at=now.isoformat())
    return TrustDecision("TRUSTED", "authorized_active_attestor", proof_id, verifier, attestor_id=result["attestor_id"], registry_id=result["registry_id"], evaluated_at=now.isoformat())
