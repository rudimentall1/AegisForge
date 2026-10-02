import hashlib
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


class CapabilityGrantError(ValueError):
    pass


from shared.outcome_contract import validate_outcome_contract, OutcomeContractError
from shared.effective_capability import EffectiveCapabilityDecision, evaluate_effective_capability



def _canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def intent_hash(intent):
    payload = intent.to_dict() if hasattr(intent, "to_dict") else intent
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def evidence_hash(evidence_ids):
    values = sorted(str(value) for value in (evidence_ids or []))
    return hashlib.sha256(_canonical(values).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CapabilityGrant:
    grant_id: str
    task_id: str
    intent_hash: str
    policy_version: str
    evidence_ids: tuple = field(default_factory=tuple)
    evidence_hash: str = ""
    authorized_action: str = ""
    authorized_target: str = ""
    authorized_scope: str = ""
    issued_at: str = ""
    expires_at: str = ""
    nonce: str = ""
    status: str = "ACTIVE"
    outcome_contract: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "grant_id": self.grant_id,
            "task_id": self.task_id,
            "intent_hash": self.intent_hash,
            "policy_version": self.policy_version,
            "evidence_ids": list(self.evidence_ids),
            "evidence_hash": self.evidence_hash,
            "authorized_action": self.authorized_action,
            "authorized_target": self.authorized_target,
            "authorized_scope": self.authorized_scope,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "status": self.status,
            "outcome_contract": self.outcome_contract,
        }

    def canonical(self):
        return _canonical(self.to_dict())

    @classmethod
    def from_dict(cls, payload):
        if not isinstance(payload, dict):
            raise CapabilityGrantError("grant_payload_required")
        required = {
            "grant_id", "task_id", "intent_hash", "policy_version",
            "evidence_ids", "evidence_hash", "authorized_action",
            "authorized_target", "authorized_scope", "issued_at",
            "expires_at", "nonce", "status", "outcome_contract",
        }
        missing = sorted(required - set(payload))
        if missing:
            raise CapabilityGrantError("grant_fields_missing:" + ",".join(missing))
        try:
            evidence_ids = tuple(sorted(str(v) for v in payload["evidence_ids"]))
        except (TypeError, ValueError):
            raise CapabilityGrantError("invalid_evidence_ids")
        grant = cls(
            grant_id=str(payload["grant_id"]),
            task_id=str(payload["task_id"]),
            intent_hash=str(payload["intent_hash"]),
            policy_version=str(payload["policy_version"]),
            evidence_ids=evidence_ids,
            evidence_hash=str(payload["evidence_hash"]),
            authorized_action=str(payload["authorized_action"]),
            authorized_target=str(payload["authorized_target"]),
            authorized_scope=str(payload["authorized_scope"]),
            issued_at=str(payload["issued_at"]),
            expires_at=str(payload["expires_at"]),
            nonce=str(payload["nonce"]),
            status=str(payload["status"]),
            outcome_contract=dict(payload["outcome_contract"]),
        )
        if not isinstance(payload["outcome_contract"], dict):
            raise CapabilityGrantError("invalid_outcome_contract")
        validate_outcome_contract(payload["outcome_contract"], action=payload.get("authorized_action"))
        # Recompute the evidence commitment before any execution path uses it.
        if grant.evidence_hash != evidence_hash(grant.evidence_ids):
            raise CapabilityGrantError("evidence_hash_mismatch")
        return grant

    def verify_binding(self, intent, evidence_ids):
        if self.status != "ACTIVE":
            raise CapabilityGrantError("grant_not_active")
        if self.intent_hash != intent_hash(intent):
            raise CapabilityGrantError("intent_hash_mismatch")
        if self.evidence_hash != evidence_hash(evidence_ids):
            raise CapabilityGrantError("evidence_hash_mismatch")
        if tuple(sorted(str(v) for v in evidence_ids)) != tuple(sorted(self.evidence_ids)):
            raise CapabilityGrantError("evidence_ids_mismatch")
        if self.authorized_action != intent.action:
            raise CapabilityGrantError("authorized_action_mismatch")
        if self.authorized_target != intent.target:
            raise CapabilityGrantError("authorized_target_mismatch")
        intent_contract = dict(getattr(intent, "parameters", {}) or {}).get("outcome_contract", {})
        validate_outcome_contract(intent_contract, action=intent.action)
        validate_outcome_contract(self.outcome_contract, action=intent.action)
        if intent_contract != self.outcome_contract:
            raise CapabilityGrantError("outcome_contract_mismatch")
        return True


def issue_capability_grant(
    task_id,
    intent,
    policy_version,
    evidence_ids=(),
    authorized_scope="",
    ttl_seconds=300,
    outcome_contract=None,
    *,
    authority_state=None,
):
    if authority_state is None:
        raise CapabilityGrantError("authority_state_required")
    effective = evaluate_effective_capability(intent, authority_state)
    if effective.decision == EffectiveCapabilityDecision.BLOCK:
        raise CapabilityGrantError("authority_blocked:" + effective.reason)
    if ttl_seconds <= 0:
        raise CapabilityGrantError("invalid_ttl")
    now = datetime.now(timezone.utc)
    evidence_ids = tuple(sorted(str(value) for value in (evidence_ids or [])))
    parameters = dict(getattr(intent, "parameters", {}) or {})
    intent_contract = parameters.get("outcome_contract", {})
    validate_outcome_contract(intent_contract, action=intent.action)
    requested_contract = intent_contract if outcome_contract is None else outcome_contract
    validate_outcome_contract(requested_contract, action=intent.action)
    if requested_contract != intent_contract:
        raise CapabilityGrantError("outcome_contract_mismatch")
    return CapabilityGrant(
        grant_id="grant_" + secrets.token_urlsafe(18),
        task_id=str(task_id),
        intent_hash=intent_hash(intent),
        policy_version=str(policy_version),
        evidence_ids=evidence_ids,
        evidence_hash=evidence_hash(evidence_ids),
        authorized_action=intent.action,
        authorized_target=intent.target,
        authorized_scope=authorized_scope,
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(seconds=ttl_seconds)).isoformat(),
        nonce=secrets.token_urlsafe(18),
        outcome_contract=dict(requested_contract),    )


def consume_capability_grant(grant, intent, evidence_ids=(), now=None):
    grant.verify_binding(intent, evidence_ids)
    current = now or datetime.now(timezone.utc)
    try:
        expires = datetime.fromisoformat(grant.expires_at)
    except ValueError as exc:
        raise CapabilityGrantError("invalid_expiry") from exc
    if current >= expires:
        raise CapabilityGrantError("grant_expired")
    return True
