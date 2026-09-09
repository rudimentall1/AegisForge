from dataclasses import dataclass, field
from typing import Any


@dataclass
class BenchmarkResult:
    name: str
    score: float
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ExperimentResult:
    experiment_id: str
    model_id: str
    baseline_id: str
    metrics: dict[str, float]
    regressions: list[str]
    decision: str
    notes: list[str] = field(default_factory=list)


@dataclass
class RuntimeProfile:
    reasoning_effort: str = "high"
    temperature: float = 0.2
    top_p: float = 0.95
    repetition_penalty: float = 1.05
    clear_thinking: bool = True
    max_tokens: int = 16384
