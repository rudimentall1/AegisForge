from shared.capability_grant import CapabilityGrantError, issue_capability_grant
from shared.capability_signing import CapabilitySigner, SignedCapabilityGrant
from shared.agent_authority import AgentAuthorityRegistry, AgentAuthorityError
from shared.signed_action_intent import SignedActionIntent, SignedActionIntentError


class ExecutionRetryAuthorizationError(ValueError):
    pass


class ExecutionRetryAuthorizer:
    """Issue fresh execution authority for a verified-safe retry."""

    def __init__(self, authority_registry, capability_signer):
        if not isinstance(authority_registry, AgentAuthorityRegistry):
            raise ExecutionRetryAuthorizationError("authority_registry_required")
        if not isinstance(capability_signer, CapabilitySigner):
            raise ExecutionRetryAuthorizationError("capability_signer_required")
        self.authority_registry = authority_registry
        self.capability_signer = capability_signer

    def authorize(self, *, attempt, intent, signed_action_intent, evidence_ids=(), ttl_seconds=300, authorized_scope=None, now=None, grant_id=None, nonce=None):
        if attempt is None:
            raise ExecutionRetryAuthorizationError("attempt_required")
        if not getattr(attempt, "task_id", ""):
            raise ExecutionRetryAuthorizationError("attempt_task_id_required")
        if not isinstance(signed_action_intent, SignedActionIntent):
            raise ExecutionRetryAuthorizationError("signed_action_intent_required")
        try:
            signed_action_intent.verify(now=now)
        except (SignedActionIntentError, TypeError, ValueError) as exc:
            raise ExecutionRetryAuthorizationError("signed_action_intent_invalid") from exc
        if signed_action_intent.intent_hash != attempt.intent_hash:
            raise ExecutionRetryAuthorizationError("retry_intent_hash_mismatch")
        if signed_action_intent.intent != intent:
            raise ExecutionRetryAuthorizationError("retry_intent_mismatch")
        try:
            authority = self.authority_registry.get(signed_action_intent.agent_identity.identity.agent_id)
        except AgentAuthorityError as exc:
            raise ExecutionRetryAuthorizationError("current_authority_unavailable") from exc
        scope = authorized_scope
        if scope is None:
            scope = intent.destination or intent.resource or ""
        try:
            grant = issue_capability_grant(
                attempt.task_id,
                intent,
                authority.policy_version,
                evidence_ids=evidence_ids,
                authorized_scope=scope,
                ttl_seconds=ttl_seconds,
                authority_state=authority.state,
                authority_context=authority,
                signed_action_intent=signed_action_intent,
                grant_id=grant_id,
                nonce=nonce,
            )
            signed_grant = self.capability_signer.sign(grant)
        except (CapabilityGrantError, TypeError, ValueError) as exc:
            raise ExecutionRetryAuthorizationError("retry_grant_issue_failed") from exc
        if signed_grant.grant.grant_id == attempt.grant_id:
            raise ExecutionRetryAuthorizationError("retry_grant_must_be_new")
        return signed_grant
