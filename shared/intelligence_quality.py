"""Non-invasive quality scoring for autonomous intelligence outputs."""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List


_GENERIC_TEXT = (
    "teams deploying ai agents, agent platforms, and autonomous workflows.",
    "deployment, orchestration, reliability, or security complexity",
    "build agent infrastructure or an autonomous workflow product around the capability demonstrated by the target.",
    "check users, competing products, adoption, deployment friction, and willingness to pay before implementation.",
)

_STOPWORDS = {
    "a", "an", "and", "around", "by", "for", "from", "in", "into", "of", "on",
    "or", "the", "to", "with", "this", "that", "is", "are", "as", "at", "be",
    "can", "will", "their", "teams", "team", "product", "technology", "technical",
}


class IntelligenceQualityEvaluator:
    """Score opportunity dossiers without changing planner state."""

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

    def evaluate_batch(self, opportunities: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        """Measure dossier duplication without using an LLM or external service."""
        items = [item for item in opportunities if isinstance(item, dict)]
        if len(items) < 2:
            return {"duplicate_rate": 0.0, "duplicate_groups": [], "count": len(items)}

        duplicate_pairs = []
        adjacency = {idx: set() for idx in range(len(items))}
        for left in range(len(items)):
            for right in range(left + 1, len(items)):
                similarity = self._dossier_similarity(items[left], items[right])
                if similarity >= 0.72:
                    duplicate_pairs.append({
                        "left": items[left].get("name"),
                        "right": items[right].get("name"),
                        "similarity": round(similarity, 3),
                    })
                    adjacency[left].add(right)
                    adjacency[right].add(left)

        duplicate_indices = {idx for idx, neighbors in adjacency.items() if neighbors}
        groups = []
        unseen = set(duplicate_indices)
        while unseen:
            seed = unseen.pop()
            group = {seed}
            frontier = [seed]
            while frontier:
                current = frontier.pop()
                for neighbor in adjacency[current] - group:
                    group.add(neighbor)
                    unseen.discard(neighbor)
                    frontier.append(neighbor)
            groups.append([items[idx].get("name") for idx in sorted(group)])

        return {
            "duplicate_rate": round(len(duplicate_indices) / len(items), 3),
            "duplicate_groups": groups,
            "duplicate_pairs": duplicate_pairs[:50],
            "count": len(items),
        }

    @classmethod
    def _dossier_similarity(cls, left: Dict[str, Any], right: Dict[str, Any]) -> float:
        fields = ("target_customer", "problem_signal", "product_thesis", "validation_experiment", "business_model")
        left_tokens = cls._tokens(" ".join(str(left.get(field, "")) for field in fields))
        right_tokens = cls._tokens(" ".join(str(right.get(field, "")) for field in fields))
        if not left_tokens or not right_tokens:
            return 0.0
        return len(left_tokens & right_tokens) / len(left_tokens | right_tokens)

    @staticmethod
    def _tokens(text: str) -> set[str]:
        return {
            token
            for token in re.findall(r"[a-z0-9][a-z0-9-]{2,}", text.lower())
            if token not in _STOPWORDS
        }

    @staticmethod
    def _evidence_score(evidence: Any, validation_evidence: Any) -> int:
        score = 0
        if isinstance(evidence, dict):
            useful = sum(
                1
                for key in (
                    "stars", "technical_maturity_score", "security_score", "has_tests",
                    "has_ci", "source", "repository_tree",
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
        fields = ("target_customer", "problem_signal", "product_thesis", "validation_experiment", "business_model")
        present = [str(opportunity.get(field, "")).strip() for field in fields]
        score = 20 * sum(bool(value) for value in present)
        generic_hits = sum(any(generic in value.lower() for generic in _GENERIC_TEXT) for value in present)
        return max(0, score - generic_hits * 15)

    @staticmethod
    def _honesty_score(opportunity: Dict[str, Any]) -> int:
        score = 100
        reasons = " ".join(str(x) for x in (opportunity.get("reasons") or []))
        if "adoption" in reasons.lower() and not opportunity.get("validation_evidence"):
            score -= 25
        if opportunity.get("validation_type") == "commercial":
            status = str(opportunity.get("validation_status", "")).upper()
            if status == "PARTIAL" and opportunity.get("confidence_delta", 0) not in (0, 0.0):
                score -= 50
        if opportunity.get("commercial_readiness") in {"VALIDATE", "EARLY_SIGNAL"} and not opportunity.get("uncertainties"):
            score -= 15
        return max(0, score)

    @staticmethod
    def _uncertainty_score(opportunity: Dict[str, Any], uncertainties: Iterable[Any]) -> int:
        items = [str(item).strip() for item in uncertainties if str(item).strip()]
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
