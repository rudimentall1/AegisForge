import base64
import hashlib
import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from shared.capability_grant import CapabilityGrant, CapabilityGrantError


class CapabilitySignatureError(ValueError):
    pass


def _canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class SignedCapabilityGrant:
    grant: CapabilityGrant
    key_id: str
    signature: str
    algorithm: str = "Ed25519"

    def payload(self):
        return {
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "grant": self.grant.to_dict(),
        }

    def to_dict(self):
        return {
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "grant": self.grant.to_dict(),
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, payload):
        if not isinstance(payload, dict):
            raise CapabilitySignatureError("signed_grant_required")
        for field in ("algorithm", "key_id", "grant", "signature"):
            if field not in payload:
                raise CapabilitySignatureError(f"signed_grant_field_missing:{field}")
        if payload["algorithm"] != "Ed25519":
            raise CapabilitySignatureError("unsupported_signature_algorithm")
        try:
            grant = CapabilityGrant.from_dict(payload["grant"])
        except (CapabilityGrantError, TypeError, ValueError) as exc:
            raise CapabilitySignatureError(str(exc)) from exc
        return cls(
            grant=grant,
            key_id=str(payload["key_id"]),
            signature=str(payload["signature"]),
            algorithm="Ed25519",
        )


class CapabilitySigner:
    """Ed25519 signer/verifier for execution authorization artifacts."""

    def __init__(self, private_key, key_id=None):
        if not isinstance(private_key, Ed25519PrivateKey):
            raise CapabilitySignatureError("ed25519_private_key_required")
        self._private_key = private_key
        public = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._public_key_bytes = public
        self.key_id = key_id or "ed25519-" + hashlib.sha256(public).hexdigest()[:16]

    @classmethod
    def generate(cls, key_id=None):
        return cls(Ed25519PrivateKey.generate(), key_id=key_id)

    @classmethod
    def load_or_create(cls, path, key_id=None):
        path = os.path.abspath(path)
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
            private_key = Ed25519PrivateKey.from_private_bytes(raw)
            return cls(private_key, key_id=key_id)
        except FileNotFoundError:
            signer = cls.generate(key_id=key_id)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            try:
                fd = os.open(path, flags, 0o600)
            except FileExistsError:
                with open(path, "rb") as handle:
                    private_key = Ed25519PrivateKey.from_private_bytes(handle.read())
                return cls(private_key, key_id=key_id)
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

    def sign_payload(self, payload):
        """Sign a canonical JSON payload for portable proof artifacts."""
        if not isinstance(payload, dict):
            raise CapabilitySignatureError("signing_payload_required")
        return self._private_key.sign(
            _canonical(payload).encode("utf-8")
        )

    def sign(self, grant):
        if not isinstance(grant, CapabilityGrant):
            raise CapabilitySignatureError("capability_grant_required")
        artifact = SignedCapabilityGrant(
            grant=grant,
            key_id=self.key_id,
            signature="",
        )
        signature = self._private_key.sign(
            _canonical(artifact.payload()).encode("utf-8")
        )
        return SignedCapabilityGrant(
            grant=grant,
            key_id=self.key_id,
            signature=base64.urlsafe_b64encode(signature).decode("ascii"),
        )

    def verify(self, signed):
        if not isinstance(signed, SignedCapabilityGrant):
            raise CapabilitySignatureError("signed_grant_required")
        if signed.algorithm != "Ed25519":
            raise CapabilitySignatureError("unsupported_signature_algorithm")
        if signed.key_id != self.key_id:
            raise CapabilitySignatureError("signer_key_id_mismatch")
        try:
            signature = base64.urlsafe_b64decode(signed.signature.encode("ascii"))
            public_key = self._private_key.public_key()
            public_key.verify(
                signature,
                _canonical(signed.payload()).encode("utf-8"),
            )
        except Exception as exc:
            raise CapabilitySignatureError("signature_invalid") from exc
        return signed.grant

    @property
    def public_key(self):
        return base64.urlsafe_b64encode(self._public_key_bytes).decode("ascii")
