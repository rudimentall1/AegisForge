"""Normal registered-case pipeline integration: bootstrap -> planner -> workers -> validator.

Agents are deterministic test doubles, but the task graph is created only by the
real MasterOrchestrator planner and executed through Worker.run_once(). No child
tasks are manually inserted by this test.
"""
import hashlib
from types import SimpleNamespace

from agents import worker as worker_module
from agents.worker import Worker
from orchestrator import master as master_module
from shared.capability_policy import ActionIntent, CapabilityDecision
from shared.evidence_ledger import EvidenceLedger
from shared.queue import TaskQueue as RealTaskQueue
from shared.research_case import (
    CaseStatus,
    ExecutionMode,
    ResearchCase,
    RoundSpec,
    research_case_binding,
)


def _case():
    spec = RoundSpec(
        round_id="normal-pipeline-round",
        technique="source_pattern",
        hypothesis="The fixed synthetic fixture produces portable integrity evidence.",
        expected_evidence_atoms=("synthetic_output",),
        falsification_criteria="The artifact digest must match the captured output.",
        priority=1,
        disclosure_deadline_days=30,
    )
    case = ResearchCase(
        case_id="normal-pipeline-case",
        target_repository="example/project",
        target_commit="a" * 40,
        scope_url="https://github.com/example/project",
        scope_digest=hashlib.sha256(b"normal-pipeline-scope").hexdigest(),
        scope_reviewed_on="2026-10-24",
        hypothesis=spec.hypothesis,
        attacker_capability="Repository-owned synthetic fixture only",
        expected_invariant="Evidence stays bound to the registered case and round.",
        falsification_criteria=spec.falsification_criteria,
        execution_mode=ExecutionMode.LOCAL,
        status=CaseStatus.READY,
        allowed_techniques=("source_pattern",),
        rounds=(spec,),
    )
    return case


class _DeterministicAgent:
    def __init__(self, role, case):
        self.role = role
        self.case = case

    def run(self, task):
        binding = research_case_binding(self.case)
        common = {
            "research_track": "evm_key_forensics",
            "source_search_rounds": 3,
            "fixture_mode": "synthetic_only",
        }
        if self.role == "source_researcher":
            return {
                **common,
                "stage": "sources",
                "source_observations": ["pinned public source reference recorded"],
            }
        if self.role == "crypto_analyst":
            return {
                **common,
                "stage": "analysis",
                "hypotheses": [{
                    "id": "synthetic-hypothesis-1",
                    "statement": "The fixed toy fixture output is reproducible.",
                    "historical_reproduction": False,
                }],
            }
        if self.role == "lab_runner":
            from agents.lab_runner.agent import LabRunner

            experiment = LabRunner.run_synthetic_entropy_demo(
                case_binding=binding
            )
            return {
                **common,
                "stage": "lab",
                "lab_experiments": [experiment],
            }
        if self.role == "validator":
            return {
                **common,
                "stage": "validation",
                "research_validation": {
                    "verdict": "NOT_REPRODUCED",
                    "historical_reproduction_confirmed": False,
                    "next_actions": ["Obtain a pinned historical implementation fixture."],
                },
            }
        raise AssertionError(f"Unexpected role: {self.role}")


class _DeterministicTechniqueRegistry:
    def dispatch(self, technique, role, task, delegate):
        assert technique == "source_pattern"
        assert role in {"source_researcher", "crypto_analyst", "lab_runner"}
        return delegate.run(task)


def _worker(role, case, queue):
    worker = Worker.__new__(Worker)
    worker.role = role
    worker.worker_id = f"e2e-{role}"
    worker.agent_id = f"e2e-{role}-agent"
    worker.agent_identity = SimpleNamespace(
        to_dict=lambda: {"agent_id": f"e2e-{role}-agent"}
    )
    worker.queue = queue
    worker.memory = SimpleNamespace(save_task=lambda task: None)
    worker.agent = _DeterministicAgent(role, case)
    worker.policy = SimpleNamespace(required_evidence=lambda intent: [])
    worker.evidence_ledger = EvidenceLedger(queue.db)
    worker._capability_decision = lambda task: (
        ActionIntent(role=role, action="research"),
        {"decision": CapabilityDecision.ALLOW, "reason": "deterministic test policy"},
    )
    worker._record_capability_decision = lambda *args: None
    worker._enqueue_execution_handoff = lambda *args: None
    return worker


def test_registered_case_runs_through_normal_planner_workers_and_validator(
    tmp_path, monkeypatch, capsys
):
    db_path = tmp_path / "normal-case-pipeline.sqlite3"
    monkeypatch.setattr(
        master_module,
        "TaskQueue",
        lambda: RealTaskQueue(db_path=db_path),
    )
    monkeypatch.setattr(
        worker_module,
        "TechniqueRegistry",
        _DeterministicTechniqueRegistry,
    )
    case = _case()
    master = master_module.MasterOrchestrator()
    queue = master.queue
    try:
        queue.register_research_case(case)

        # The real bootstrap creates the first root from the registered RoundSpec.
        assert master.bootstrap() is True
        root_row = queue.db.execute(
            "SELECT round_id, round_spec_id FROM queue "
            "WHERE parent_task_id IS NULL AND research_case_id = ?",
            (case.case_id,),
        ).fetchall()
        assert len(root_row) == 1
        assert root_row[0] == ("normal-pipeline-round", "normal-pipeline-round")

        expected_roles = [
            "source_researcher",
            "crypto_analyst",
            "lab_runner",
            "validator",
        ]
        for role in expected_roles:
            worker = _worker(role, case, queue)
            assert worker.run_once() is True, f"worker failed for role={role}"
            capsys.readouterr()
            # The real planner must decide and enqueue the next child.
            plan = master.planner.plan()
            if role != "validator":
                assert plan["created"] >= 1, (
                    f"planner did not create the next stage after {role}: {plan}"
                )

        rows = queue.db.execute(
            "SELECT id, role, status, parent_task_id FROM queue "
            "WHERE research_case_id = ?",
            (case.case_id,),
        ).fetchall()
        by_id = {row[0]: row for row in rows}
        roots = [row for row in rows if row[3] is None]
        assert len(roots) == 1
        ordered = [roots[0]]
        while True:
            children = [row for row in rows if row[3] == ordered[-1][0]]
            if not children:
                break
            assert len(children) == 1, "unexpected branch fan-out in vertical-slice fixture"
            ordered.append(children[0])
        assert [row[1] for row in ordered] == expected_roles
        assert all(row[2] == "completed" for row in ordered)
        assert len(ordered) == len(rows), "pipeline left an unlinked or unexpected task"

        lab_result = queue.get_result(
            queue.db.execute(
                "SELECT id FROM queue WHERE research_case_id = ? AND role = 'lab_runner'",
                (case.case_id,),
            ).fetchone()[0]
        )
        assert lab_result["local_experiment_evidence"]["status"] == "PERSISTED", lab_result["local_experiment_evidence"]
        assert lab_result["local_experiment_evidence"]["integrity_only"] is True
        assert lab_result["local_experiment_evidence"]["authenticated_execution"] is False

        # Bootstrap consumes the completed validator result; it must not infer
        # a positive verdict from the source, analyst, or lab result.
        assert master.bootstrap() is False
        round_status = queue.db.execute(
            "SELECT status, verdict FROM round_transparency WHERE case_id = ? AND round_id = ?",
            (case.case_id, "normal-pipeline-round"),
        ).fetchone()
        assert round_status == ("COMPLETED", "NOT_REPRODUCED")
    finally:
        queue.db.close()
