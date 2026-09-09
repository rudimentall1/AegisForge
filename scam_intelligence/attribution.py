from typing import Iterable

from .schemas import Attribution, Evidence


class AttributionEngine:
    """
    Conservative defensive attribution scoring.

    Confidence represents support from the supplied evidence.
    It is not a statement of legal guilt or identity.
    """

    HIGH = 0.85
    MEDIUM = 0.60

    def score(
        self,
        entity: str,
        evidence: Iterable[Evidence],
    ) -> Attribution:
        evidence = list(evidence)

        verified = [
            item for item in evidence
            if item.verified
        ]

        if not verified:
            return Attribution(
                entity=entity,
                confidence=0.0,
                status="UNVERIFIED",
            )

        # Independent evidence should increase confidence,
        # but no single observation can produce certainty.
        weighted = []

        for item in verified:
            strength = max(0.0, min(1.0, item.strength))

            # Cap the contribution of one individual observation.
            weighted.append(min(strength, 0.70))

        # Evidence aggregation with diminishing returns.
        confidence = 1.0
        for strength in weighted:
            confidence *= 1.0 - strength * 0.55

        confidence = 1.0 - confidence

        confidence = min(0.95, confidence)

        if confidence >= self.HIGH:
            status = "HIGH_CONFIDENCE"
        elif confidence >= self.MEDIUM:
            status = "MEDIUM_CONFIDENCE"
        else:
            status = "LOW_CONFIDENCE"

        return Attribution(
            entity=entity,
            confidence=round(confidence, 4),
            evidence_ids=[
                item.evidence_id
                for item in verified
            ],
            status=status,
        )
