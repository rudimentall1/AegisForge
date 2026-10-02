import hashlib
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


class CapabilityGrantError(ValueError):
    pass


from shared.outcome_contract import validate_outcome_contract, OutcomeContractError
from shared.effective_capability import EffectiveCapabilityDecision, evaluate_effective_capability
from shared.signed_action_intent import SignedActionIntent, SignedActionIntentError



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
    agent_id: str
    authority_epoch: int
    authority_state: str
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
    signed_action_intent: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "grant_id": self.grant_id,
            "task_id": self.task_id,
            "agent_id": self.agent_id,
            "authority_epoch": self.authority_epoch,
            "authority_state": self.authority_state,
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
            "signed_action_intent": self.signed_action_intent,
        }

    def canonical(self):
        return _canonical(self.to_dict())

    @classmethod
    def from_dict(cls, payload):
        if not isinstance(payload, dict):
            raise CapabilityGrantError("grant_payload_required")
        required = {
            "grant_id", "task_id", "agent_id", "authority_epoch", "authority_state",
            "intent_hash", "policy_version",
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
            agent_id=str(payload["agent_id"]),
            authority_epoch=int(payload["authority_epoch"]),
            authority_state=str(payload["authority_state"]),
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
            signed_action_intent=dict(payload.get("signed_action_intent") or {}),
        )
        if not isinstance(payload["outcome_contract"], dict):
            raise CapabilityGrantError("invalid_outcome_contract")
        validate_outcome_contract(payload["outcome_contract"], action=payload.get("authorized_action"))
        if grant.signed_action_intent:
            try:
                signed_intent = SignedActionIntent.from_dict(grant.signed_action_intent)
                signed_intent.verify()
            except (SignedActionIntentError, TypeError, ValueError) as exc:
                raise CapabilityGrantError("signed_action_intent_invalid") from exc
            if signed_intent.intent_hash != grant.intent_hash:
                raise CapabilityGrantError("signed_action_intent_hash_mismatch")
        # Recompute the evidence commitment before any execution path uses it.
        if grant.evidence_hash != evidence_hash(grant.evidence_ids):
            raise CapabilityGrantError("evidence_hash_mismatch")
        return grant

    def verify_binding(self, intent, evidence_ids):
        if self.status != "ACTIVE":
            raise CapabilityGrantError("grant_not_active")
        if self.intent_hash != intent_hash(intent):
            raise CapabilityGrantError("intent_hash_mismatch")
        if self.signed_action_intent:
            try:
                signed_intent = SignedActionIntent.from_dict(self.signed_action_intent)
                signed_intent.verify()
            except (SignedActionIntentError, TypeError, ValueError) as exc:
                raise CapabilityGrantError("signed_action_intent_invalid") from exc
            if signed_intent.intent_hash != self.intent_hash:
                raise CapabilityGrantError("signed_action_intent_hash_mismatch")
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
    authority_context=None,
    signed_action_intent=None,
):
    if authority_context is None:
        raise CapabilityGrantError("authority_context_required")
    if not getattr(authority_context, "agent_id", None):
        raise CapabilityGrantError("authority_agent_id_required")
    if int(getattr(authority_context, "authority_epoch", 0)) <= 0:
        raise CapabilityGrantError("authority_epoch_required")
    if authority_state is not None and authority_state != authority_context.state:
        raise CapabilityGrantError("authority_state_mismatch")
    if str(policy_version) != str(authority_context.policy_version):
        raise CapabilityGrantError("authority_policy_version_mismatch")
    signed_intent_payload = {}
    if signed_action_intent is not None:
        if not isinstance(signed_action_intent, SignedActionIntent):
            raise CapabilityGrantError("signed_action_intent_required")
        try:
            signed_action_intent.verify()
        except SignedActionIntentError as exc:
            raise CapabilityGrantError("signed_action_intent_invalid") from exc
        if signed_action_intent.intent_hash != intent_hash(intent):
            raise CapabilityGrantError("signed_action_intent_hash_mismatch")
        signed_intent_payload = signed_action_intent.to_dict()
    authority_state = authority_context.state
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
        agent_id=str(authority_context.agent_id),
        authority_epoch=int(authority_context.authority_epoch),
        authority_state=authority_context.state.value,
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
        outcome_contract=dict(requested_contract),
        signed_action_intent=signed_intent_payload,
    )


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
