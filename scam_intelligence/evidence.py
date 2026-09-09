from typing import Iterable, List

from .schemas import Evidence


class EvidenceEngine:
    """
    Stores observations separately from conclusions.

    The engine never converts an observation directly into
    an accusation. Attribution is a later stage.
    """

    def collect(self, observations: Iterable[Evidence]) -> List[Evidence]:
        result = []

        for item in observations:
            if not item.evidence_id:
                continue

            if not item.source:
                continue

            if not item.observation:
                continue

            result.append(item)

        return result

    @staticmethod
    def verified_strength(evidence: Iterable[Evidence]) -> float:
        verified = [
            max(0.0, min(1.0, item.strength))
            for item in evidence
            if item.verified
        ]

        if not verified:
            return 0.0

        # Multiple independent observations increase confidence,
        # but the score is capped at 1.0.
        combined = 1.0

        for strength in verified:
            combined *= 1.0 - strength

        return round(1.0 - combined, 4)
