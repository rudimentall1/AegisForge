import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from shared.action_intent import ActionIntent
from shared.agent_identity_signing import (
    AgentIdentitySigner,
    SignedAgentIdentity,
    AgentIdentitySignatureError,
)


SCHEMA_VERSION = "signed-action-intent-v1"


class SignedActionIntentError(ValueError):
    pass


def _canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def intent_hash(intent):
    payload = intent.to_dict() if hasattr(intent, "to_dict") else intent
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SignedActionIntent:
    intent: ActionIntent
    intent_hash: str
    agent_identity: SignedAgentIdentity
    issued_at: str
    nonce: str
    signature: str
    algorithm: str = "Ed25519"
    schema_version: str = SCHEMA_VERSION
    expires_at: str = ""

    def payload(self):
        return {
            "algorithm": self.algorithm,
            "agent_identity": self.agent_identity.to_dict(),
            "expires_at": self.expires_at,
            "intent": self.intent.to_dict(),
            "intent_hash": self.intent_hash,
            "issued_at": self.issued_at,
            "nonce": self.nonce,
            "schema_version": self.schema_version,
        }

    def to_dict(self):
        return {**self.payload(), "signature": self.signature}

    def canonical(self):
        return _canonical(self.payload())

    @classmethod
    def from_dict(cls, payload):
        if not isinstance(payload, dict):
            raise SignedActionIntentError("signed_action_intent_required")
        required = {
            "algorithm", "agent_identity", "expires_at", "intent",
            "intent_hash", "issued_at", "nonce", "schema_version", "signature",
        }
        missing = sorted(required - set(payload))
        if missing:
            raise SignedActionIntentError(
                "signed_action_intent_fields_missing:" + ",".join(missing)
            )
        if payload["algorithm"] != "Ed25519" or payload["schema_version"] != SCHEMA_VERSION:
            raise SignedActionIntentError("unsupported_signed_action_intent")
        try:
            identity = SignedAgentIdentity.from_dict(payload["agent_identity"])
            raw_intent = dict(payload["intent"])
            intent = ActionIntent(**raw_intent)
        except (AgentIdentitySignatureError, TypeError, ValueError) as exc:
            raise SignedActionIntentError(str(exc)) from exc
        return cls(
            intent=intent,
            intent_hash=str(payload["intent_hash"]),
            agent_identity=identity,
            issued_at=str(payload["issued_at"]),
            nonce=str(payload["nonce"]),
            signature=str(payload["signature"]),
            algorithm="Ed25519",
            schema_version=SCHEMA_VERSION,
            expires_at=str(payload["expires_at"]),
        )

    def verify(self, now=None):
        if self.agent_identity.identity.agent_id != self.intent.agent_id:
            raise SignedActionIntentError("agent_identity_mismatch")
        expected_hash = intent_hash(self.intent)
        if self.intent_hash != expected_hash:
            raise SignedActionIntentError("intent_hash_mismatch")
        try:
            AgentIdentitySigner.verify_identity(self.agent_identity)
        except AgentIdentitySignatureError as exc:
            raise SignedActionIntentError(str(exc)) from exc
        try:
            signature = base64.urlsafe_b64decode(self.signature.encode("ascii"))
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            public_raw = base64.urlsafe_b64decode(self.agent_identity.public_key.encode("ascii"))
            Ed25519PublicKey.from_public_bytes(public_raw).verify(
                signature, self.canonical().encode("utf-8")
            )
        except Exception as exc:
            raise SignedActionIntentError("signature_invalid") from exc
        if self.expires_at:
            try:
                expiry = datetime.fromisoformat(self.expires_at)
            except ValueError as exc:
                raise SignedActionIntentError("invalid_expiry") from exc
            if (now or datetime.now(timezone.utc)) >= expiry:
                raise SignedActionIntentError("intent_expired")
        return True


class ActionIntentSigner:
    def __init__(self, agent_identity_signer):
        if not isinstance(agent_identity_signer, AgentIdentitySigner):
            raise SignedActionIntentError("agent_identity_signer_required")
        self.agent_identity_signer = agent_identity_signer

    def sign(self, intent, ttl_seconds=300, nonce=None):
        if not isinstance(intent, ActionIntent):
            raise SignedActionIntentError("action_intent_required")
        if intent.agent_id != self.agent_identity_signer.identity.agent_id:
            raise SignedActionIntentError("agent_identity_mismatch")
        if ttl_seconds <= 0:
            raise SignedActionIntentError("invalid_ttl")
        now = datetime.now(timezone.utc)
        identity = self.agent_identity_signer.sign_identity()
        artifact = SignedActionIntent(
            intent=intent,
            intent_hash=intent_hash(intent),
            agent_identity=identity,
            issued_at=now.isoformat(),
            nonce=nonce or hashlib.sha256(
                f"{self.agent_identity_signer.key_id}:{now.isoformat()}".encode()
            ).hexdigest()[:32],
            signature="",
            expires_at=(now + __import__("datetime").timedelta(seconds=ttl_seconds)).isoformat(),
        )
        signature = self.agent_identity_signer._private_key.sign(
            artifact.canonical().encode("utf-8")
        )
        return SignedActionIntent(
            intent=artifact.intent,
            intent_hash=artifact.intent_hash,
            agent_identity=artifact.agent_identity,
            issued_at=artifact.issued_at,
            nonce=artifact.nonce,
            signature=base64.urlsafe_b64encode(signature).decode("ascii"),
            expires_at=artifact.expires_at,
        )
