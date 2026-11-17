import base64
import hashlib
import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from shared.agent_identity import AgentIdentity


SCHEMA_VERSION = "signed-agent-identity-v1"


class AgentIdentitySignatureError(ValueError):
    pass


def _canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class SignedAgentIdentity:
    identity: AgentIdentity
    public_key: str
    key_id: str
    signature: str
    algorithm: str = "Ed25519"
    schema_version: str = SCHEMA_VERSION

    def payload(self):
        return {
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "identity": self.identity.to_dict(),
            "public_key": self.public_key,
            "schema_version": self.schema_version,
        }

    def to_dict(self):
        return {**self.payload(), "signature": self.signature}

    @classmethod
    def from_dict(cls, payload):
        if not isinstance(payload, dict):
            raise AgentIdentitySignatureError("signed_agent_identity_required")
        required = {"algorithm", "key_id", "identity", "public_key", "schema_version", "signature"}
        missing = sorted(required - set(payload))
        if missing:
            raise AgentIdentitySignatureError("signed_agent_identity_fields_missing:" + ",".join(missing))
        if payload["algorithm"] != "Ed25519" or payload["schema_version"] != SCHEMA_VERSION:
            raise AgentIdentitySignatureError("unsupported_signed_agent_identity")
        identity = AgentIdentity(
            agent_id=str(payload["identity"]["agent_id"]),
            role=str(payload["identity"]["role"]),
            schema_version=str(payload["identity"].get("schema_version", "agent-identity-v1")),
        )
        return cls(
            identity=identity,
            public_key=str(payload["public_key"]),
            key_id=str(payload["key_id"]),
            signature=str(payload["signature"]),
        )


class AgentIdentitySigner:
    """Ed25519 identity key holder for cryptographically authenticated agents."""

    def __init__(self, private_key, agent_id, role):
        if not isinstance(private_key, Ed25519PrivateKey):
            raise AgentIdentitySignatureError("ed25519_private_key_required")
        self._private_key = private_key
        self.identity = AgentIdentity(agent_id=str(agent_id), role=str(role))
        public = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._public_key_bytes = public
        self.public_key = base64.urlsafe_b64encode(public).decode("ascii")
        self.key_id = "agent-ed25519-" + hashlib.sha256(public).hexdigest()[:16]

    @classmethod
    def generate(cls, agent_id, role):
        return cls(Ed25519PrivateKey.generate(), agent_id, role)

    @classmethod
    def load_or_create(cls, path, agent_id, role):
        path = os.path.abspath(path)
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
            return cls(Ed25519PrivateKey.from_private_bytes(raw), agent_id, role)
        except FileNotFoundError:
            signer = cls.generate(agent_id, role)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(signer._private_key.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption(),
                    ))
            except Exception:
                try:
                    os.unlink(path)
                except OSError:
                    pass
                raise
            return signer

    def sign_identity(self):
        artifact = SignedAgentIdentity(
            identity=self.identity,
            public_key=self.public_key,
            key_id=self.key_id,
            signature="",
        )
        signature = self._private_key.sign(_canonical(artifact.payload()).encode("utf-8"))
        return SignedAgentIdentity(
            identity=self.identity,
            public_key=self.public_key,
            key_id=self.key_id,
            signature=base64.urlsafe_b64encode(signature).decode("ascii"),
        )

    @staticmethod
    def verify_identity(signed):
        if not isinstance(signed, SignedAgentIdentity):
            raise AgentIdentitySignatureError("signed_agent_identity_required")
        try:
            public_raw = base64.urlsafe_b64decode(signed.public_key.encode("ascii"))
            public = Ed25519PublicKey.from_public_bytes(public_raw)
            expected_key_id = "agent-ed25519-" + hashlib.sha256(public_raw).hexdigest()[:16]
            if expected_key_id != signed.key_id:
                raise AgentIdentitySignatureError("agent_identity_key_id_mismatch")
            signature = base64.urlsafe_b64decode(signed.signature.encode("ascii"))
            public.verify(signature, _canonical(signed.payload()).encode("utf-8"))
        except AgentIdentitySignatureError:
            raise
        except Exception as exc:
            raise AgentIdentitySignatureError("agent_identity_signature_invalid") from exc
        return signed.identity
