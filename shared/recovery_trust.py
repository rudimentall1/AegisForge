import base64
import hashlib
from dataclasses import dataclass


class RecoveryTrustError(ValueError):
    pass


@dataclass(frozen=True)
class RecoveryAttestor:
    key_id: str
    public_key: str
    name: str
    enabled: bool = True


class RecoveryAttestorRegistry:
    """Explicit trust anchors for signed recovery proofs."""

    def __init__(self, attestors=None):
        self._attestors = {}
        for attestor in attestors or ():
            self.register(attestor)

    def register(self, attestor):
        if not isinstance(attestor, RecoveryAttestor):
            raise RecoveryTrustError("attestor_required")
        try:
            raw = base64.urlsafe_b64decode(attestor.public_key.encode("ascii"))
        except Exception as exc:
            raise RecoveryTrustError("invalid_attestor_public_key") from exc
        if len(raw) != 32:
            raise RecoveryTrustError("invalid_attestor_public_key")
        expected = "ed25519-" + hashlib.sha256(raw).hexdigest()[:16]
        if attestor.key_id != expected:
            raise RecoveryTrustError("attestor_key_id_mismatch")
        if not attestor.name.strip():
            raise RecoveryTrustError("attestor_name_required")
        self._attestors[attestor.key_id] = attestor

    def get(self, key_id):
        return self._attestors.get(key_id)

    def require(self, key_id, public_key):
        attestor = self.get(key_id)
        if attestor is None:
            raise RecoveryTrustError("untrusted_attestor")
        if not attestor.enabled:
            raise RecoveryTrustError("attestor_disabled")
        if attestor.public_key != public_key:
            raise RecoveryTrustError("attestor_key_mismatch")
        return attestor

    def to_dict(self):
        return {
            key_id: {
                "key_id": attestor.key_id,
                "public_key": attestor.public_key,
                "name": attestor.name,
                "enabled": attestor.enabled,
            }
            for key_id, attestor in sorted(self._attestors.items())
        }
