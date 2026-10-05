"""Non-invasive quality scoring for autonomous intelligence outputs."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List


_GENERIC_TEXT = (
    "teams deploying ai agents, agent platforms, and autonomous workflows.",
    "deployment, orchestration, reliability, or security complexity",
    "build agent infrastructure or an autonomous workflow product around the capability demonstrated by the target.",
    "check users, competing products, adoption, deployment friction, and willingness to pay before implementation.",
)


class IntelligenceQualityEvaluator:
    """Score opportunity dossiers without changing planner state.

    The evaluator deliberately measures evidence quality rather than business
    attractiveness. It is safe to run against historical or live results.
    """

    def evaluate(self, opportunity: Dict[str, Any]) -> Dict[str, Any]:
        evidence = opportunity.get("evidence")
        validation_evidence = opportunity.get("validation_evidence")
        uncertainties = opportunity.get("uncertainties") or []

        evidence_score = self._evidence_score(evidence, validation_evidence)
        specificity_score = self._specificity_score(opportunity)
        honesty_score = self._honesty_score(opportunity)
        uncertainty_score = self._uncertainty_score(opportunity, uncertainties)

        total = round(
            0.35 * evidence_score
            + 0.25 * specificity_score
            + 0.25 * honesty_score
            + 0.15 * uncertainty_score
        )

        return {
            "score": total,
            "dimensions": {
                "evidence": evidence_score,
                "specificity": specificity_score,
                "honesty": honesty_score,
                "uncertainty": uncertainty_score,
            },
            "labels": self._labels(opportunity, uncertainties),
        }

    @staticmethod
    def _evidence_score(
        evidence: Any,
        validation_evidence: Any,
    ) -> int:
        score = 0
        if isinstance(evidence, dict):
            useful = sum(
                1
                for key in (
                    "stars",
                    "technical_maturity_score",
                    "security_score",
                    "has_tests",
                    "has_ci",
                    "source",
                    "repository_tree",
                )
                if evidence.get(key) is not None
            )
            score = min(70, useful * 10)
        if isinstance(validation_evidence, dict):
            if validation_evidence.get("status"):
                score += 10
            if validation_evidence.get("type"):
                score += 5
            if validation_evidence.get("metric"):
                score += 10
            if validation_evidence.get("value") is not None:
                score += 5
        return min(100, score)

    @classmethod
    def _specificity_score(cls, opportunity: Dict[str, Any]) -> int:
        fields = (
            "target_customer",
            "problem_signal",
            "product_thesis",
            "validation_experiment",
            "business_model",
        )
        present = [str(opportunity.get(field, "")).strip() for field in fields]
        score = 20 * sum(bool(value) for value in present)
        generic_hits = sum(
            any(generic in value.lower() for generic in _GENERIC_TEXT)
            for value in present
        )
        return max(0, score - generic_hits * 15)

    @staticmethod
    def _honesty_score(opportunity: Dict[str, Any]) -> int:
        score = 100
        reasons = " ".join(str(x) for x in (opportunity.get("reasons") or []))
        lower_reasons = reasons.lower()
        if "adoption" in lower_reasons and not opportunity.get("validation_evidence"):
            score -= 25
        if opportunity.get("validation_type") == "commercial":
            status = str(opportunity.get("validation_status", "")).upper()
            if status == "PARTIAL" and opportunity.get("confidence_delta", 0) not in (0, 0.0):
                score -= 50
        if opportunity.get("commercial_readiness") in {"VALIDATE", "EARLY_SIGNAL"}:
            if not opportunity.get("uncertainties"):
                score -= 15
        return max(0, score)

    @staticmethod
    def _uncertainty_score(
        opportunity: Dict[str, Any],
        uncertainties: Iterable[Any],
    ) -> int:
        items: List[str] = [str(item).strip() for item in uncertainties if str(item).strip()]
        readiness = str(opportunity.get("commercial_readiness", "")).upper()
        if readiness in {"VALIDATE", "EARLY_SIGNAL"}:
            return 100 if items else 35
        return 100 if items else 70

    @staticmethod
    def _labels(opportunity: Dict[str, Any], uncertainties: Iterable[Any]) -> List[str]:
        labels: List[str] = []
        if opportunity.get("evidence"):
            labels.append("observed_evidence")
        if opportunity.get("problem_signal") or opportunity.get("product_thesis"):
            labels.append("inference")
        if opportunity.get("validation_experiment") or opportunity.get("business_model"):
            labels.append("hypothesis")
        if list(uncertainties):
            labels.append("unknowns_explicit")
        return labels
