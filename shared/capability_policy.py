from dataclasses import dataclass
from enum import Enum


class CapabilityDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_EVIDENCE = "REQUIRE_EVIDENCE"


@dataclass
class ActionIntent:
    role: str
    action: str
    target: str = ""
    resource: str = ""
    destination: str = ""
    data_scope: str = ""
    irreversible: bool = False
    requires_network: bool = False
    requires_shell: bool = False
    requires_filesystem: bool = False
    financial: bool = False
    privileged: bool = False
    read_only: bool = True
    evidence_required: bool = False
    parameters: dict = None

    def to_dict(self):
        return {
            "role": self.role, "action": self.action, "target": self.target,
            "resource": self.resource, "destination": self.destination,
            "data_scope": self.data_scope, "irreversible": self.irreversible,
            "requires_network": self.requires_network, "requires_shell": self.requires_shell,
            "requires_filesystem": self.requires_filesystem, "financial": self.financial,
            "privileged": self.privileged, "read_only": self.read_only,
            "evidence_required": self.evidence_required,
            "parameters": dict(self.parameters or {}),
        }


class CapabilityPolicy:
    VERSION = "capability-policy-v1"
    ROLE_ALLOWED_ACTIONS = {
        "researcher": {"research", "read_public_docs"},
        "analyst": {"analyze", "inspect_evidence"},
        "developer": {"inspect_code", "modify_code", "run_tests", "deploy", "publish", "delete", "transfer", "release", "api_request", "mcp_tool_call"},
        "security_checker": {"security_scan", "inspect_code", "verify"},
        "opportunity_hunter": {"identify_opportunities", "research"},
        "validator": {"validate", "verify"},
        "model_researcher": {"model_research", "research"},
    }

    SENSITIVE_ACTIONS = {"modify_code", "deploy", "publish", "delete", "transfer", "release", "api_request", "mcp_tool_call"}
    SENSITIVE_EVIDENCE_REQUIREMENTS = {
        "modify_code": {"tests_passed"},
        "deploy": {"tests_passed", "security_scan_passed", "rollback_ready"},
        "publish": {"tests_passed", "security_scan_passed", "artifact_integrity"},
        "delete": {"recovery_ready"},
        "transfer": {"authorization_confirmed", "destination_allowed", "simulation_passed"},
        "release": {"tests_passed", "security_scan_passed", "artifact_integrity"},
        "api_request": {"destination_allowed"},
        "mcp_tool_call": {"destination_allowed"},
    }

    EVIDENCE_SOURCE_ROLES = {
        "tests_passed": {"developer", "validator"},
        "security_scan_passed": {"security_checker", "validator"},
        "rollback_ready": {"developer", "validator"},
        "rollback_or_recovery_ready": {"developer", "validator"},
        "artifact_integrity": {"developer", "security_checker", "validator"},
        "recovery_ready": {"developer", "validator"},
        "authorization_confirmed": {"validator"},
        "destination_allowed": {"validator", "security_checker"},
        "simulation_passed": {"validator", "security_checker"},
        "financial_authorization": {"validator"},
        "privilege_scope_verified": {"security_checker", "validator"},
        "explicit_evidence": {"validator"},
    }

    def __init__(self):
        self.blocked_targets = {"unknown_external_endpoint", "production_database", "production_environment"}
        self.blocked_destinations = {"production_database", "production", "production_environment", "production_api", "unauthorized_external_destination"}
        self.blocked_data_scopes = {"credentials", "private_keys", "secrets", "api_keys", "passwords"}
        self.network_allowed = True
        self.shell_allowed = True
        self.filesystem_allowed = True

    def evidence_source_allowed(self, claim_type: str, source_role: str):
        return source_role in self.EVIDENCE_SOURCE_ROLES.get(claim_type, set())

    def required_evidence(self, intent: ActionIntent):
        requirements = set(self.SENSITIVE_EVIDENCE_REQUIREMENTS.get(intent.action, set()))
        if intent.financial: requirements.update({"financial_authorization", "destination_allowed"})
        if intent.privileged: requirements.add("privilege_scope_verified")
        if intent.irreversible: requirements.add("rollback_or_recovery_ready")
        if intent.evidence_required and not requirements: requirements.add("explicit_evidence")
        return sorted(requirements)

    def check(self, intent: ActionIntent):
        if intent.target in self.blocked_targets:
            return {"decision": CapabilityDecision.BLOCK, "reason": "blocked_target"}
        if intent.destination in self.blocked_destinations:
            return {"decision": CapabilityDecision.BLOCK, "reason": "blocked_destination"}
        if intent.data_scope in self.blocked_data_scopes:
            return {"decision": CapabilityDecision.BLOCK, "reason": "blocked_data_scope"}
        if intent.action not in self.ROLE_ALLOWED_ACTIONS.get(intent.role, set()):
            return {"decision": CapabilityDecision.BLOCK, "reason": "action_not_allowed_for_role"}
        if intent.requires_shell and not self.shell_allowed:
            return {"decision": CapabilityDecision.BLOCK, "reason": "shell_disabled"}
        if intent.requires_network and not self.network_allowed:
            return {"decision": CapabilityDecision.BLOCK, "reason": "network_disabled"}
        if intent.requires_filesystem and not self.filesystem_allowed:
            return {"decision": CapabilityDecision.BLOCK, "reason": "filesystem_disabled"}
        if (intent.action in self.SENSITIVE_ACTIONS or not intent.read_only or intent.irreversible
                or intent.financial or intent.privileged or intent.evidence_required):
            return {"decision": CapabilityDecision.REQUIRE_EVIDENCE, "reason": "evidence_required_for_sensitive_action"}
        return {"decision": CapabilityDecision.ALLOW, "reason": "policy_pass"}