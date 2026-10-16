from types import SimpleNamespace

from agents.worker import Worker
from shared.queue import TaskQueue as RealTaskQueue
from shared.research_case import ResearchCase, RoundSpec
from shared.techniques.registry import TechniqueRegistry
import orchestrator.master as master_module


class FakeAgent:
    def __init__(self, value=None):
        self.value = value or {"status": "completed", "evidence": ["bounded fixture"]}
        self.calls = 0

    def run(self, task):
        self.calls += 1
        return dict(self.value)


def test_registry_dispatches_source_pattern_to_role_agent():
    task = SimpleNamespace(payload={"research_case": None, "round_spec": None})
    agent = FakeAgent()
    result = TechniqueRegistry().dispatch("source_pattern", "source_researcher", task, agent)

    assert agent.calls == 1
    assert result["technique"] == "source_pattern"
    assert result["technique_dispatch"]["status"] == "DISPATCHED"
    assert result["technique_dispatch"]["role"] == "source_researcher"


def test_registry_dispatches_crypto_and_runtime_to_specialist_roles():
    registry = TechniqueRegistry()
    task = SimpleNamespace(payload={})
    crypto = FakeAgent()
    runtime = FakeAgent()

    crypto_result = registry.dispatch(
        "crypto_primitive_analysis", "crypto_analyst", task, crypto
    )
    runtime_result = registry.dispatch("runtime_probe", "lab_runner", task, runtime)

    assert crypto_result["technique_dispatch"]["status"] == "DISPATCHED"
    assert runtime_result["technique_dispatch"]["status"] == "DISPATCHED"
    assert crypto.calls == runtime.calls == 1


def test_unimplemented_and_unknown_techniques_fail_closed():
    registry = TechniqueRegistry()
    task = SimpleNamespace(payload={})

    for name in ("fuzzing", "symbolic_execution", "formal_verification", "supply_chain", "not_a_technique"):
        result = registry.dispatch(name, "source_researcher", task, FakeAgent())
        assert result["status"] == "NOT_IMPLEMENTED"
        assert result["error_type"] == "TechniqueNotImplemented"
        assert result["execution_performed"] is False


def test_technique_role_mismatch_does_not_call_agent():
    task = SimpleNamespace(payload={})
    agent = FakeAgent()
    result = TechniqueRegistry().dispatch("runtime_probe", "crypto_analyst", task, agent)

    assert result["status"] == "NOT_IMPLEMENTED"
    assert result["error"] == "role_not_supported:crypto_analyst"
    assert agent.calls == 0


def test_worker_resolves_technique_from_round_root_and_child(tmp_path):
    queue = RealTaskQueue(db_path=tmp_path / "queue.db")
    case_id = "dispatch-case-001"
    case = ResearchCase(
        case_id=case_id,
        target_repository="example/project",
        target_commit="a" * 40,
        scope_url="https://example.com/scope",
        scope_digest="b" * 64,
        scope_reviewed_on="2026-10-16",
        hypothesis="A bounded local check tests an invariant.",
        attacker_capability="An unprivileged caller invokes a public method.",
        expected_invariant="State remains consistent.",
        falsification_criteria="Counter-tests preserve the invariant.",
        allowed_techniques=("source_pattern",),
        rounds=(RoundSpec(
            round_id="round-source",
            technique="source_pattern",
            hypothesis="Inspect a pinned source revision.",
            expected_evidence_atoms=("source location",),
            falsification_criteria="No matching source pattern exists.",
            disclosure_deadline_days=30,
        ),),
    )
    queue.register_research_case(case)
    root_id = queue.add(
        "root", role="source_researcher", research_case_id=case_id,
        round_id="round-source",
    )
    child_id = queue.add(
        "child", role="crypto_analyst", research_case_id=case_id,
        parent_task_id=root_id,
    )
    worker = object.__new__(Worker)
    worker.queue = queue

    assert worker._resolve_round_spec(root_id, case).technique == "source_pattern"
    assert worker._resolve_round_spec(child_id, case).technique == "source_pattern"
    queue.db.close()


def test_master_assigns_root_role_from_round_technique(tmp_path, monkeypatch):
    db_path = tmp_path / "queue.db"
    monkeypatch.setattr(
        master_module,
        "TaskQueue",
        lambda: RealTaskQueue(db_path=db_path),
    )
    master = master_module.MasterOrchestrator()
    case = ResearchCase(
        case_id="dispatch-root-roles",
        target_repository="example/project",
        target_commit="a" * 40,
        scope_url="https://example.com/scope",
        scope_digest="b" * 64,
        scope_reviewed_on="2026-10-16",
        hypothesis="A bounded local check tests an invariant.",
        attacker_capability="An unprivileged caller invokes a public method.",
        expected_invariant="State remains consistent.",
        falsification_criteria="Counter-tests preserve the invariant.",
        allowed_techniques=(
            "source_pattern", "differential_revision",
            "crypto_primitive_analysis", "runtime_probe",
        ),
        rounds=(
            RoundSpec("source", "source_pattern", "Inspect source.", ("source location",), "No matching pattern.", disclosure_deadline_days=30),
            RoundSpec("diff", "differential_revision", "Compare revisions.", ("revision diff",), "No relevant difference.", disclosure_deadline_days=30),
            RoundSpec("crypto", "crypto_primitive_analysis", "Review crypto primitives.", ("primitive use",), "No relevant primitive.", disclosure_deadline_days=30),
            RoundSpec("runtime", "runtime_probe", "Run bounded synthetic probe.", ("probe output",), "Probe does not reproduce.", disclosure_deadline_days=30),
        ),
    )
    master.queue.register_research_case(case)

    assert master.bootstrap() is True
    rows = master.queue.db.execute(
        "SELECT round_id, role FROM queue WHERE research_case_id = ? AND parent_task_id IS NULL",
        (case.case_id,),
    ).fetchall()
    assert dict(rows) == {
        "source": "source_researcher",
        "diff": "source_researcher",
        "crypto": "crypto_analyst",
        "runtime": "lab_runner",
    }
    master.queue.db.close()
