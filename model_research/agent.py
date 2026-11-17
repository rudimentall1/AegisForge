import uuid

from shared.task import Task
from .benchmark import benchmark_manifest
from .lab import WEIGHTS
from .runtime_policy import get_profile


class ModelResearcher:

    def run(self, task: Task) -> Task:
        parent = task.payload.get("parent_result")

        result = {
            "research_id": str(uuid.uuid4()),
            "status": "research_plan_created",
            "objective": (
                "Improve security reasoning while preserving general "
                "capability, agent reliability and runtime efficiency"
            ),
            "methodology": [
                "baseline",
                "hypothesis",
                "controlled_experiment",
                "benchmark",
                "calibration",
                "regression",
                "keep_or_reject",
            ],
            "score_weights": WEIGHTS,
            "runtime_profiles": {
                role: get_profile(role)
                for role in (
                    "researcher",
                    "analyst",
                    "developer",
                    "security_checker",
                    "model_researcher",
                    "opportunity_hunter",
                    "master",
                )
            },
            "benchmark_manifest": benchmark_manifest(),
            "parent_security_context": parent,
            "next_actions": [
                "Select a reproducible base model",
                "Run baseline capability benchmark",
                "Run security benchmark",
                "Evaluate runtime profile",
                "Record metrics",
                "Reject regressions automatically",
                "Promote only reproducible improvements",
            ],
        }

        task.result = result
        task.status = "model_researched"
        return task
