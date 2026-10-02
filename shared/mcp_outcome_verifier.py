import hashlib
import json

from shared.capability_grant import intent_hash
from shared.http_executor import HttpApiExecutor, HttpExecutorError


class McpOutcomeVerificationError(ValueError):
    pass


class McpOutcomeVerifier:
    """Independently verifies an MCP action through a read-only verification call.

    The verification contract is supplied by the authorized intent:
    parameters.verification.endpoint
    parameters.verification.tool
    parameters.verification.arguments
    parameters.verification.expected_state

    The verifier never trusts the original tools/call response as proof.
    """

    def __init__(self, allowed_hosts=None, timeout=10, session=None):
        self.transport = HttpApiExecutor(
            allowed_hosts=allowed_hosts,
            timeout=timeout,
            session=session,
        )

    def verify(self, intent, receipt):
        payload = receipt.to_dict() if hasattr(receipt, "to_dict") else dict(receipt)
        if payload.get("status") != "EXECUTED":
            raise McpOutcomeVerificationError("receipt_not_executed")
        expected_hash = intent_hash(intent)
        if payload.get("intent_hash") != expected_hash:
            raise McpOutcomeVerificationError("receipt_intent_hash_mismatch")
        if payload.get("action") != intent.action:
            raise McpOutcomeVerificationError("receipt_action_mismatch")

        params = dict(getattr(intent, "parameters", {}) or {})
        verification = params.get("verification")
        if not isinstance(verification, dict):
            raise McpOutcomeVerificationError("mcp_verification_contract_required")

        endpoint = verification.get("endpoint") or intent.target
        tool = str(verification.get("tool") or "").strip()
        arguments = verification.get("arguments", {})
        if not tool:
            raise McpOutcomeVerificationError("mcp_verification_tool_required")
        if not isinstance(arguments, dict):
            raise McpOutcomeVerificationError("mcp_verification_arguments_invalid")

        transport_intent = type(
            "VerificationIntent",
            (),
            {
                "target": endpoint,
                "parameters": {
                    "method": "POST",
                    "url": endpoint,
                    "headers": verification.get("headers") or {},
                    "body": {
                        "jsonrpc": "2.0",
                        "id": verification.get("request_id", "aegisforge-verify"),
                        "method": "tools/call",
                        "params": {"name": tool, "arguments": arguments},
                    },
                },
            },
        )()

        try:
            observed = self.transport.execute(transport_intent)
        except HttpExecutorError as exc:
            raise McpOutcomeVerificationError(str(exc)) from exc

        observed_state = observed.get("body")
        if isinstance(observed_state, dict) and "result" in observed_state:
            observed_state = observed_state["result"]

        expected_state = verification.get("expected_state")
        if expected_state is not None and observed_state != expected_state:
            raise McpOutcomeVerificationError("mcp_expected_state_mismatch")

        checks = [
            "receipt_status",
            "intent_binding",
            "action_binding",
            "independent_mcp_read",
        ]
        canonical = json.dumps(
            {
                "receipt_id": payload.get("receipt_id"),
                "intent_hash": expected_hash,
                "action": intent.action,
                "target": str(intent.target),
                "verification_tool": tool,
                "observed": observed_state,
                "checks": checks,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return {
            "outcome_id": hashlib.sha256(canonical.encode()).hexdigest(),
            "status": "PROVEN",
            "verifier": "mcp_independent_read_v1",
            "receipt_id": payload.get("receipt_id"),
            "intent_hash": expected_hash,
            "action": intent.action,
            "target": str(intent.target),
            "observed_state": observed_state,
            "checks": checks,
        }
