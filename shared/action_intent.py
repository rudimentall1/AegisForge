import json

from shared.capability_policy import ActionIntent


ROLE_DEFAULT_INTENTS = {
    "researcher": {
        "action": "research",
        "resource": "public_sources",
        "destination": "public_web",
        "data_scope": "public",
        "requires_network": True,
        "read_only": True,
    },
    "analyst": {
        "action": "analyze",
        "resource": "research_results",
        "destination": "internal",
        "data_scope": "research_evidence",
        "read_only": True,
    },
    "developer": {
        "action": "inspect_code",
        "resource": "repository",
        "destination": "workspace",
        "data_scope": "source_code",
        "requires_filesystem": True,
        "read_only": True,
    },
    "security_checker": {
        "action": "security_scan",
        "resource": "repository",
        "destination": "workspace",
        "data_scope": "source_code",
        "requires_filesystem": True,
        "read_only": True,
    },
    "opportunity_hunter": {
        "action": "identify_opportunities",
        "resource": "research_results",
        "destination": "internal",
        "data_scope": "research_evidence",
        "read_only": True,
    },
    "validator": {
        "action": "validate",
        "resource": "validation_target",
        "destination": "internal",
        "data_scope": "validation_evidence",
        "read_only": True,
    },
    "model_researcher": {
        "action": "model_research",
        "resource": "public_sources",
        "destination": "public_web",
        "data_scope": "public",
        "requires_network": True,
        "read_only": True,
    },
}


INTENT_FIELDS = {
    "action",
    "target",
    "resource",
    "destination",
    "data_scope",
    "irreversible",
    "requires_network",
    "requires_shell",
    "requires_filesystem",
    "financial",
    "privileged",
    "read_only",
    "evidence_required",
    "parameters",
}


def _explicit_intent(task):
    payload = getattr(task, "payload", {}) or {}
    value = payload.get("capability_intent")
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def default_capability_intent(role: str):
    """Return a copy of the role's declared baseline capability intent."""
    return dict(ROLE_DEFAULT_INTENTS.get(role, {}))


def build_action_intent(role: str, task):
    values = default_capability_intent(role)
    explicit = _explicit_intent(task)

    for key, value in explicit.items():
        if key in INTENT_FIELDS:
            values[key] = value

    values["role"] = role
    values.setdefault("action", "")
    return ActionIntent(**values)