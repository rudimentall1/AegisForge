from dataclasses import dataclass


SCHEMA_VERSION = "trust-authority-v1"

TRUSTED = "TRUSTED"
UNTRUSTED = "UNTRUSTED"
EXPIRED = "EXPIRED"

AUTHORITY_CONTINUE = "AUTHORITY_CONTINUE"
AUTHORITY_RESTRICT = "AUTHORITY_RESTRICT"
RE_ATTEST_REQUIRED = "RE_ATTEST_REQUIRED"


class TrustAuthorityError(ValueError):
    pass


@dataclass(frozen=True)
class AuthorityTrustDecision:
    status: str
    decision: str
    reason: str
    proof_id: str
    attestor_id: str | None = None
    registry_id: str | None = None

    def to_dict(self):
        return {
            "schema_version": SCHEMA_VERSION,
            "status": self.status,
            "decision": self.decision,
            "reason": self.reason,
            "proof_id": self.proof_id,
            "attestor_id": self.attestor_id,
            "registry_id": self.registry_id,
        }


def trust_to_authority(trust_decision):
    if trust_decision is None:
        raise TrustAuthorityError("trust_decision_required")

    status = getattr(trust_decision, "status", None)
    proof_id = getattr(trust_decision, "proof_id", "")
    attestor_id = getattr(trust_decision, "attestor_id", None)
    registry_id = getattr(trust_decision, "registry_id", None)
    reason = getattr(trust_decision, "reason", "")

    if not proof_id:
        raise TrustAuthorityError("proof_id_required")

    if status == TRUSTED:
        return AuthorityTrustDecision(
            status=TRUSTED,
            decision=AUTHORITY_CONTINUE,
            reason="trusted_attested_outcome",
            proof_id=proof_id,
            attestor_id=attestor_id,
            registry_id=registry_id,
        )

    if status == EXPIRED:
        return AuthorityTrustDecision(
            status=EXPIRED,
            decision=RE_ATTEST_REQUIRED,
            reason="attestation_expired",
            proof_id=proof_id,
            attestor_id=attestor_id,
            registry_id=registry_id,
        )

    if status == UNTRUSTED:
        return AuthorityTrustDecision(
            status=UNTRUSTED,
            decision=AUTHORITY_RESTRICT,
            reason=reason or "untrusted_outcome",
            proof_id=proof_id,
            attestor_id=attestor_id,
            registry_id=registry_id,
        )

    raise TrustAuthorityError("unknown_trust_status")
