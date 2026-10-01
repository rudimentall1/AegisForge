import hashlib
import json
from pathlib import Path

from shared.capability_grant import intent_hash


class OutcomeVerificationError(ValueError):
    pass


class FilesystemOutcomeVerifier:
    """Independently verify a filesystem execution result.

    The verifier does not trust the executor's receipt.result as proof. It
    inspects the configured filesystem and checks that the receipt is bound to
    the supplied intent and that the claimed deletion actually occurred.
    """

    def __init__(self, root):
        self.root = Path(root).resolve()

    def _resolve_target(self, intent):
        raw = str(getattr(intent, "target", "") or "")
        if not raw:
            raise OutcomeVerificationError("filesystem_target_required")
        target = (self.root / raw).resolve()
        try:
            target.relative_to(self.root)
        except ValueError as exc:
            raise OutcomeVerificationError("filesystem_path_escape") from exc
        if target == self.root:
            raise OutcomeVerificationError("filesystem_root_protected")
        return target

    @staticmethod
    def _receipt_dict(receipt):
        if hasattr(receipt, "to_dict"):
            return receipt.to_dict()
        if isinstance(receipt, dict):
            return dict(receipt)
        raise OutcomeVerificationError("receipt_required")

    def verify(self, intent, receipt):
        payload = self._receipt_dict(receipt)
        expected_intent_hash = intent_hash(intent)
        checks = []

        if payload.get("status") != "EXECUTED":
            raise OutcomeVerificationError("receipt_not_executed")
        checks.append("receipt_status")

        if payload.get("intent_hash") != expected_intent_hash:
            raise OutcomeVerificationError("receipt_intent_hash_mismatch")
        checks.append("intent_binding")

        if payload.get("action") != intent.action:
            raise OutcomeVerificationError("receipt_action_mismatch")
        checks.append("action_binding")

        target = self._resolve_target(intent)
        if target.exists():
            raise OutcomeVerificationError("filesystem_effect_not_observed")
        checks.append("filesystem_absence")

        claimed = payload.get("result")
        if not isinstance(claimed, dict) or claimed.get("deleted") != str(target.relative_to(self.root)):
            raise OutcomeVerificationError("receipt_result_mismatch")
        checks.append("receipt_result")

        canonical = json.dumps(
            {
                "receipt_id": payload.get("receipt_id"),
                "intent_hash": expected_intent_hash,
                "action": intent.action,
                "target": str(intent.target),
                "observed_state": "ABSENT",
                "checks": checks,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        outcome_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return {
            "outcome_id": outcome_id,
            "status": "PROVEN",
            "verifier": "filesystem_independent_v1",
            "receipt_id": payload.get("receipt_id"),
            "intent_hash": expected_intent_hash,
            "action": intent.action,
            "target": str(intent.target),
            "observed_state": "ABSENT",
            "checks": checks,
        }

class ArtifactOutcomeVerifier:
    """Independently verify a staged artifact publication."""

    def __init__(self, root):
        self.root = Path(root).resolve()

    def _resolve_target(self, intent):
        raw = str(getattr(intent, "target", "") or "")
        if not raw:
            raise OutcomeVerificationError("artifact_target_required")
        target = (self.root / raw).resolve()
        try:
            target.relative_to(self.root)
        except ValueError as exc:
            raise OutcomeVerificationError("artifact_path_escape") from exc
        if target == self.root:
            raise OutcomeVerificationError("artifact_target_invalid")
        return target

    def verify(self, intent, receipt):
        payload = self._receipt_dict(receipt)
        expected_intent_hash = intent_hash(intent)
        checks = []

        if payload.get("status") != "EXECUTED":
            raise OutcomeVerificationError("receipt_not_executed")
        checks.append("receipt_status")

        if payload.get("intent_hash") != expected_intent_hash:
            raise OutcomeVerificationError("receipt_intent_hash_mismatch")
        checks.append("intent_binding")

        if payload.get("action") != "publish":
            raise OutcomeVerificationError("receipt_action_mismatch")
        checks.append("action_binding")

        target = self._resolve_target(intent)
        if not target.is_file():
            raise OutcomeVerificationError("artifact_effect_not_observed")
        checks.append("artifact_presence")

        content = target.read_bytes()
        observed_sha256 = hashlib.sha256(content).hexdigest()
        expected_sha256 = (intent.parameters or {}).get("sha256")
        if observed_sha256 != expected_sha256:
            raise OutcomeVerificationError("artifact_hash_mismatch")
        checks.append("artifact_hash")

        claimed = payload.get("result")
        if not isinstance(claimed, dict) or claimed.get("sha256") != observed_sha256:
            raise OutcomeVerificationError("receipt_result_mismatch")
        checks.append("receipt_result")

        canonical = json.dumps(
            {
                "receipt_id": payload.get("receipt_id"),
                "intent_hash": expected_intent_hash,
                "action": "publish",
                "target": str(intent.target),
                "observed_state": "PRESENT",
                "sha256": observed_sha256,
                "checks": checks,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        outcome_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return {
            "outcome_id": outcome_id,
            "status": "PROVEN",
            "verifier": "artifact_independent_v1",
            "receipt_id": payload.get("receipt_id"),
            "intent_hash": expected_intent_hash,
            "action": "publish",
            "target": str(intent.target),
            "observed_state": "PRESENT",
            "sha256": observed_sha256,
            "checks": checks,
        }
