from statistics import mean
from .schemas import ExperimentResult


WEIGHTS = {
    "general_capability": 0.30,
    "secure_code_reasoning": 0.25,
    "repository_analysis": 0.20,
    "tool_reliability": 0.15,
    "runtime_efficiency": 0.10,
}


def weighted_score(metrics: dict[str, float]) -> float:
    return sum(
        metrics.get(name, 0.0) * weight
        for name, weight in WEIGHTS.items()
    )


def compare(
    experiment_id: str,
    model_id: str,
    baseline_id: str,
    metrics: dict[str, float],
    baseline_metrics: dict[str, float],
) -> ExperimentResult:
    regressions = []

    for name, baseline in baseline_metrics.items():
        current = metrics.get(name, baseline)
        if baseline > 0 and current < baseline * 0.95:
            regressions.append(
                f"{name}: {current:.4f} < regression gate {baseline * 0.95:.4f}"
            )

    current_score = weighted_score(metrics)
    baseline_score = weighted_score(baseline_metrics)

    decision = "KEEP"
    if regressions or current_score < baseline_score:
        decision = "REJECT"

    return ExperimentResult(
        experiment_id=experiment_id,
        model_id=model_id,
        baseline_id=baseline_id,
        metrics=metrics,
        regressions=regressions,
        decision=decision,
        notes=[
            f"weighted_score={current_score:.4f}",
            f"baseline_weighted_score={baseline_score:.4f}",
        ],
    )


def summarize(values: list[float]) -> float:
    return mean(values) if values else 0.0
