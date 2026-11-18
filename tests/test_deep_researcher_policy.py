from agents.deep_researcher.agent import DeepResearcher
from shared.action_intent import build_action_intent
from shared.capability_policy import CapabilityDecision, CapabilityPolicy
from shared.research_case import validate_worker_case_binding
from shared.task import Task


def test_deep_researcher_is_read_only_and_allowed_without_case_binding():
    task = Task(task_id="deep-research-1", description="deployment research")
    intent = build_action_intent("deep_researcher", task, agent_id="deep-researcher-test")
    decision = CapabilityPolicy().check(intent)

    assert decision["decision"] == CapabilityDecision.ALLOW
    assert intent.action == "research"
    assert intent.requires_network is True
    assert intent.read_only is True
    assert intent.financial is False
    assert validate_worker_case_binding("deep_researcher", None, None) is None
    assert DeepResearcher.name == "deep_researcher"
