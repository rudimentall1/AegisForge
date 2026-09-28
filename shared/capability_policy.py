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

    def to_dict(self):
        return {
            "role": self.role,
            "action": self.action,
            "target": self.target,
            "resource": self.resource,
            "destination": self.destination,
            "data_scope": self.data_scope,
            "irreversible": self.irreversible,
            "requires_network": self.requires_network,
            "requires_shell": self.requires_shell,
            "requires_filesystem": self.requires_filesystem,
            "financial": self.financial,
            "privileged": self.privileged,
            "read_only": self.read_only,
            "evidence_required": self.evidence_required,
        }


class CapabilityPolicy:
    ROLE_ALLOWED_ACTIONS = {
        "researcher": {"research", "read_public_docs"},
        "analyst": {"analyze", "inspect_evidence"},
        "developer": {
            "inspect_code",
            "modify_code",
            "run_tests",
            "deploy",
            "publish",
            "delete",
            "transfer",
            "release",
        },
        "security_checker": {"security_scan", "inspect_code", "verify"},
        "opportunity_hunter": {"identify_opportunities", "research"},
        "validator": {"validate", "verify"},
        "model_researcher": {"model_research", "research"},
    }

    def __init__(self):
        self.blocked_targets = {
            "unknown_external_endpoint",
            "production_database",
        }
        self.blocked_destinations = {
            "production_database",
        }
        self.network_allowed = True
        self.shell_allowed = True
        self.filesystem_allowed = True

    def check(self, intent: ActionIntent):
        if intent.target in self.blocked_targets:
            return {
                "decision": CapabilityDecision.BLOCK,
                "reason": "blocked_target",
            }

        if intent.destination in self.blocked_destinations:
            return {
                "decision": CapabilityDecision.BLOCK,
                "reason": "blocked_destination",
            }

        allowed_actions = self.ROLE_ALLOWED_ACTIONS.get(intent.role, set())
        if intent.action not in allowed_actions:
            return {
                "decision": CapabilityDecision.BLOCK,
                "reason": "action_not_allowed_for_role",
            }

        if intent.requires_shell and not self.shell_allowed:
            return {
                "decision": CapabilityDecision.BLOCK,
                "reason": "shell_disabled",
            }

        if intent.requires_network and not self.network_allowed:
            return {
                "decision": CapabilityDecision.BLOCK,
                "reason": "network_disabled",
            }

        if intent.requires_filesystem and not self.filesystem_allowed:
            return {
                "decision": CapabilityDecision.BLOCK,
                "reason": "filesystem_disabled",
            }

        if (
            intent.irreversible
            or intent.financial
            or intent.privileged
            or intent.evidence_required
        ):
            return {
                "decision": CapabilityDecision.REQUIRE_EVIDENCE,
                "reason": "evidence_required_for_sensitive_action",
            }

        return {
            "decision": CapabilityDecision.ALLOW,
            "reason": "policy_pass",
        }
