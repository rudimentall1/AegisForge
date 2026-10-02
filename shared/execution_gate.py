import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

from shared.capability_grant import CapabilityGrantError, consume_capability_grant
from shared.capability_signing import CapabilitySignatureError, SignedCapabilityGrant
from shared.capability_policy import CapabilityPolicy
from shared.capability_grant_store import CapabilityGrantStore, CapabilityGrantStoreError
from shared.agent_authority import AgentAuthorityRegistry, AgentAuthorityError


class ExecutionGateError(ValueError):
    pass


@dataclass(frozen=True)
class ExecutionReceipt:
    receipt_id: str
    task_id: str
    grant_id: str
    nonce: str
    intent_hash: str
    policy_version: str
    action: str
    target: str
    authorized_scope: str
    status: str
    executed_at: str
    result: object = None
    error: str = ""
    agent_id: str = ""
    authority_epoch: int = 0
    authority_state: str = ""


    def to_dict(self):
        return {
            "receipt_id": self.receipt_id,
            "task_id": self.task_id,
            "grant_id": self.grant_id,
            "nonce": self.nonce,
            "intent_hash": self.intent_hash,
            "policy_version": self.policy_version,
            "action": self.action,
            "target": self.target,
            "authorized_scope": self.authorized_scope,
            "status": self.status,
            "executed_at": self.executed_at,
            "result": self.result,
            "error": self.error,
            "agent_id": self.agent_id,
            "authority_epoch": self.authority_epoch,
            "authority_state": self.authority_state,
        }


class ExecutionGate:
    """Fail-closed boundary between verified authority and real execution."""

    CONSUMPTION_TABLE = "capability_grant_consumptions"

    def __init__(self, db=None, policy=None, signer=None, authority_registry=None):
        self.db = db
        self.policy = policy or CapabilityPolicy()
        self.signer = signer
        self.authority_registry = authority_registry
        self.grant_store = CapabilityGrantStore(self.db) if self.db is not None else None
        if self.db is not None:
            self.db.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {self.CONSUMPTION_TABLE} (
                    nonce TEXT PRIMARY KEY,
                    grant_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    consumed_at TEXT NOT NULL,
                    receipt_id TEXT NOT NULL
                )
                """
            )
            self.db.commit()

    def _grant(self, value):
        if not isinstance(value, SignedCapabilityGrant):
            raise ExecutionGateError("signed_grant_required")
        if self.signer is None:
            raise ExecutionGateError("signer_required")
        try:
            return self.signer.verify(value), value
        except CapabilitySignatureError as exc:
            raise ExecutionGateError(str(exc)) from exc

    @staticmethod
    def _scope(intent):
        return intent.destination or intent.resource or ""

    def _consume_nonce(self, grant, receipt_id, now):
        if self.db is None:
            raise ExecutionGateError("replay_store_required")
        try:
            self.db.execute(
                f"""
                INSERT INTO {self.CONSUMPTION_TABLE}
                (nonce, grant_id, task_id, consumed_at, receipt_id)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    grant.nonce,
                    grant.grant_id,
                    grant.task_id,
                    now,
                    receipt_id,
                ),
            )
            self.db.commit()
        except Exception as exc:
            self.db.rollback()
            if "UNIQUE" in str(exc).upper():
                raise ExecutionGateError("grant_replayed") from exc
            raise

    def authorize(self, grant, intent, evidence_ids=(), now=None):
        if grant is None:
            raise ExecutionGateError("grant_required")

        grant, _signed = self._grant(grant)

        if grant.policy_version != self.policy.VERSION:
            raise ExecutionGateError("policy_version_mismatch")

        if self.authority_registry is None:
            raise ExecutionGateError("authority_registry_required")

        try:
            authority = self.authority_registry.get(grant.agent_id)
        except AgentAuthorityError as exc:
            raise ExecutionGateError(str(exc)) from exc
        if grant.authority_epoch != authority.authority_epoch:
            raise ExecutionGateError("authority_epoch_mismatch")
        if grant.authority_state != authority.state.value:
            raise ExecutionGateError("authority_state_mismatch")
        if grant.policy_version != authority.policy_version:
            raise ExecutionGateError("authority_policy_version_mismatch")

        if self.grant_store is not None:
            try:
                status = self.grant_store.ensure_registered(_signed)
            except CapabilityGrantStoreError as exc:
                raise ExecutionGateError(str(exc)) from exc
            if status != "ACTIVE":
                raise ExecutionGateError("grant_revoked" if status == "REVOKED" else "grant_replayed")

        try:
            consume_capability_grant(
                grant,
                intent,
                evidence_ids=evidence_ids,
                now=now,
            )
        except CapabilityGrantError as exc:
            raise ExecutionGateError(str(exc)) from exc

        expected_scope = self._scope(intent)
        if grant.authorized_scope != expected_scope:
            raise ExecutionGateError("authorized_scope_mismatch")

        return grant

    def execute(self, grant, intent, executor, evidence_ids=(), now=None):
        """Authorize exactly once, then invoke executor.

        The executor is deliberately injected: this module does not perform
        network, shell, filesystem, financial, or other real-world actions.
        """
        if not callable(executor):
            raise ExecutionGateError("executor_required")

        grant = self.authorize(
            grant,
            intent,
            evidence_ids=evidence_ids,
            now=now,
        )

        executed_at = (now or datetime.now(timezone.utc)).isoformat()
        receipt_id = "receipt_" + secrets.token_urlsafe(18)

        if self.grant_store is not None:
            try:
                self.grant_store.consume(grant.grant_id, receipt_id, executed_at)
            except CapabilityGrantStoreError as exc:
                raise ExecutionGateError(str(exc)) from exc

        self._consume_nonce(grant, receipt_id, executed_at)

        try:
            result = executor()
            receipt = ExecutionReceipt(
                receipt_id=receipt_id,
                task_id=grant.task_id,
                grant_id=grant.grant_id,
                nonce=grant.nonce,
                intent_hash=grant.intent_hash,
                policy_version=grant.policy_version,
                action=intent.action,
                target=intent.target,
                authorized_scope=grant.authorized_scope,
                status="EXECUTED",
                executed_at=executed_at,
                result=result,
                agent_id=grant.agent_id,
                authority_epoch=grant.authority_epoch,
                authority_state=grant.authority_state,
            )
        except Exception as exc:
            receipt = ExecutionReceipt(
                receipt_id=receipt_id,
                task_id=grant.task_id,
                grant_id=grant.grant_id,
                nonce=grant.nonce,
                intent_hash=grant.intent_hash,
                policy_version=grant.policy_version,
                action=intent.action,
                target=intent.target,
                authorized_scope=grant.authorized_scope,
                status="FAILED",
                executed_at=executed_at,
                error=f"{type(exc).__name__}: {str(exc)[:500]}",
                agent_id=grant.agent_id,
                authority_epoch=grant.authority_epoch,
                authority_state=grant.authority_state,
            )
        return receipt
