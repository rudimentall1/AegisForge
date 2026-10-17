from types import SimpleNamespace

import pytest

from shared.techniques.base import TechniqueContext
from shared.techniques.registry import TechniqueRegistry


EXPECTED_TECHNIQUES = {
    "source_pattern",
    "differential_revision",
    "crypto_primitive_analysis",
    "runtime_probe",
    "fuzzing",
    "symbolic_execution",
    "formal_verification",
    "supply_chain",
}
PLACEHOLDER_TECHNIQUES = {
    "fuzzing",
    "symbolic_execution",
    "formal_verification",
    "supply_chain",
}


class RecordingDelegate:
    def __init__(self, result=None):
        self.calls = []
        self.result = {"status": "completed", "evidence": ["bounded-test"]} if result is None else result

    def run(self, task):
        self.calls.append(task)
        return self.result


def make_task(**payload):
    return SimpleNamespace(task_id="task-1", payload=payload)


def test_registry_exposes_exact_allowlisted_technique_set():
    assert TechniqueRegistry().names == EXPECTED_TECHNIQUES


@pytest.mark.parametrize("technique", sorted(PLACEHOLDER_TECHNIQUES))
def test_placeholder_techniques_report_not_implemented_without_delegate_call(technique):
    delegate = RecordingDelegate()
    result = TechniqueRegistry().dispatch(
        technique=technique,
        role="lab_runner",
        task=make_task(),
        delegate=delegate,
    )

    assert result == {
        "status": "NOT_IMPLEMENTED",
        "technique": technique,
        "error": "technique_not_implemented",
        "error_type": "TechniqueNotImplemented",
        "execution_performed": False,
    }
    assert delegate.calls == []


def test_unknown_technique_fails_closed_without_delegate_call():
    delegate = RecordingDelegate()

    result = TechniqueRegistry().dispatch(
        technique="unregistered_technique",
        role="source_researcher",
        task=make_task(),
        delegate=delegate,
    )

    assert result["status"] == "NOT_IMPLEMENTED"
    assert result["technique"] == "unregistered_technique"
    assert result["error"] == "unknown_technique"
    assert result["execution_performed"] is False
    assert delegate.calls == []


def test_unsupported_role_fails_closed_without_delegate_call():
    delegate = RecordingDelegate()

    result = TechniqueRegistry().dispatch(
        technique="runtime_probe",
        role="source_researcher",
        task=make_task(),
        delegate=delegate,
    )

    assert result["status"] == "NOT_IMPLEMENTED"
    assert result["error"] == "role_not_supported:source_researcher"
    assert result["execution_performed"] is False
    assert delegate.calls == []


def test_delegating_technique_calls_existing_agent_once_and_preserves_result():
    task = make_task()
    delegate = RecordingDelegate()

    result = TechniqueRegistry().dispatch(
        technique="source_pattern",
        role="source_researcher",
        task=task,
        delegate=delegate,
    )

    assert delegate.calls == [task]
    assert result["status"] == "completed"
    assert result["evidence"] == ["bounded-test"]
    assert result["technique"] == "source_pattern"
    assert result["technique_dispatch"] == {
        "status": "DISPATCHED",
        "adapter": "agents.techniques.source_pattern",
        "role": "source_researcher",
    }


def test_delegating_technique_without_agent_fails_closed():
    result = TechniqueRegistry().dispatch(
        technique="source_pattern",
        role="source_researcher",
        task=make_task(),
        delegate=None,
    )

    assert result["status"] == "NOT_IMPLEMENTED"
    assert result["error"] == "role_agent_unavailable"
    assert result["execution_performed"] is False


def test_registry_passes_structured_case_and_round_spec_to_technique_context():
    research_case = object()
    round_spec = object()
    task = make_task(research_case=research_case, round_spec=round_spec)
    registry = TechniqueRegistry()
    captured = {}

    class ContextProbe:
        name = "context_probe"
        supported_roles = frozenset({"source_researcher"})

        def run(self, context: TechniqueContext, delegate):
            captured["context"] = context
            return {"status": "PROBED"}

    registry._techniques["context_probe"] = ContextProbe()
    result = registry.dispatch(
        technique="context_probe",
        role="source_researcher",
        task=task,
        delegate=None,
    )

    assert result == {"status": "PROBED"}
    assert captured["context"].task is task
    assert captured["context"].research_case is research_case
    assert captured["context"].round_spec is round_spec
