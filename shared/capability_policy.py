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
    irreversible: bool = False
    requires_network: bool = False
    requires_shell: bool = False


class CapabilityPolicy:

    def __init__(self):
        self.blocked_targets = {
            "unknown_external_endpoint",
            "production_database",
        }

        self.network_allowed = True
        self.shell_allowed = True


    def check(self, intent: ActionIntent):

        if intent.target in self.blocked_targets:
            return {
                "decision": CapabilityDecision.BLOCK,
                "reason": "blocked_target"
            }


        if intent.requires_shell and not self.shell_allowed:
            return {
                "decision": CapabilityDecision.BLOCK,
                "reason": "shell_disabled"
            }


        if intent.requires_network and not self.network_allowed:
            return {
                "decision": CapabilityDecision.BLOCK,
                "reason": "network_disabled"
            }


        if intent.irreversible:
            return {
                "decision": CapabilityDecision.REQUIRE_EVIDENCE,
                "reason": "irreversible_action"
            }


        return {
            "decision": CapabilityDecision.ALLOW,
            "reason": "policy_pass"
        }
