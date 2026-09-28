from shared.action_intent import build_action_intent
from shared.capability_policy import CapabilityPolicy, CapabilityDecision
from shared.task import Task


def make_task(description="", payload=None):
    return Task(
        task_id="1",
        description=description,
        payload=payload or {},
        status="running",
    )


def test_role_baseline_does_not_parse_arbitrary_description():
    task = make_task(
        "Analyze a project that can deploy, publish, delete, and transfer assets."
    )
    intent = build_action_intent("analyst", task)

    assert intent.action == "analyze"
    assert intent.irreversible is False
    assert intent.financial is False
    assert intent.privileged is False


def test_structured_intent_overrides_role_baseline():
    task = make_task(
        "normal analysis text mentioning deploy",
        payload={
            "capability_intent": {
                "action": "deploy",
                "resource": "application",
                "destination": "staging",
                "irreversible": True,
                "read_only": False,
            }
        },
    )
    intent = build_action_intent("developer", task)

    assert intent.action == "deploy"
    assert intent.destination == "staging"
    assert intent.irreversible is True
    assert intent.read_only is False


def test_structured_unknown_external_target_blocks():
    task = make_task(
        payload={
            "capability_intent": {
                "action": "verify",
                "target": "unknown_external_endpoint",
            }
        }
    )
    decision = CapabilityPolicy().check(build_action_intent("validator", task))
    assert decision["decision"] == CapabilityDecision.BLOCK
