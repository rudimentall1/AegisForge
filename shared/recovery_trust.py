import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone


class RecoveryTrustError(ValueError):
    pass


class RecoveryAttestorStatus:
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


_ALLOWED_TRANSITIONS = {
    RecoveryAttestorStatus.ACTIVE: {
        RecoveryAttestorStatus.SUSPENDED,
        RecoveryAttestorStatus.REVOKED,
    },
    RecoveryAttestorStatus.SUSPENDED: {
        RecoveryAttestorStatus.ACTIVE,
        RecoveryAttestorStatus.REVOKED,
    },
    RecoveryAttestorStatus.REVOKED: set(),
}


@dataclass(frozen=True)
class RecoveryAttestor:
    key_id: str
    public_key: str
    name: str
    enabled: bool = True


class RecoveryAttestorRegistry:
    """Explicit trust anchors and auditable lifecycle for recovery attestors."""

    def __init__(self, attestors=None):
        self._attestors = {}
        self._status = {}
        self._history = {}
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
        status = (
            RecoveryAttestorStatus.ACTIVE
            if attestor.enabled
            else RecoveryAttestorStatus.SUSPENDED
        )
        self._status[attestor.key_id] = status
        self._history[attestor.key_id] = [
            {
                "from_status": None,
                "to_status": status,
                "occurred_at": datetime.now(timezone.utc).isoformat(),
                "reason": "registered",
            }
        ]

    def get(self, key_id):
        return self._attestors.get(key_id)

    def status(self, key_id):
        if key_id not in self._attestors:
            raise RecoveryTrustError("untrusted_attestor")
        return self._status[key_id]

    def transition(self, key_id, new_status, reason):
        if key_id not in self._attestors:
            raise RecoveryTrustError("untrusted_attestor")
        if new_status not in _ALLOWED_TRANSITIONS:
            raise RecoveryTrustError("invalid_attestor_status")
        current = self._status[key_id]
        if new_status not in _ALLOWED_TRANSITIONS[current]:
            raise RecoveryTrustError("invalid_attestor_transition")
        if not isinstance(reason, str) or not reason.strip():
            raise RecoveryTrustError("attestor_transition_reason_required")
        self._status[key_id] = new_status
        self._history[key_id].append(
            {
                "from_status": current,
                "to_status": new_status,
                "occurred_at": datetime.now(timezone.utc).isoformat(),
                "reason": reason.strip(),
            }
        )
        return new_status

    def history(self, key_id):
        if key_id not in self._attestors:
            raise RecoveryTrustError("untrusted_attestor")
        return [dict(event) for event in self._history[key_id]]

    def require(self, key_id, public_key):
        attestor = self.get(key_id)
        if attestor is None:
            raise RecoveryTrustError("untrusted_attestor")
        if not attestor.enabled:
            raise RecoveryTrustError("attestor_disabled")
        if self._status[key_id] == RecoveryAttestorStatus.SUSPENDED:
            raise RecoveryTrustError("attestor_suspended")
        if self._status[key_id] == RecoveryAttestorStatus.REVOKED:
            raise RecoveryTrustError("attestor_revoked")
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
                "status": self._status[key_id],
                "history": self.history(key_id),
            }
            for key_id, attestor in sorted(self._attestors.items())
        }
