from shared.action_intent import build_action_intent
from shared.task import Task


def test_deploy_requires_evidence():

    task = Task(
        task_id="1",
        description="deploy application",
        payload={},
        status="running",
    )

    intent = build_action_intent(
        "developer",
        task,
    )

    assert intent.irreversible is True


def test_external_endpoint_detected():

    task = Task(
        task_id="2",
        description="call unknown external endpoint",
        payload={},
        status="running",
    )

    intent = build_action_intent(
        "worker",
        task,
    )

    assert intent.target == "unknown_external_endpoint"
