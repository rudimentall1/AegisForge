from typing import Any, Dict

from .case import make_case_id
from .schemas import ScamCase


class ScamHunter:
    """
    Entry point for scam-intelligence investigations.

    Blockchain/API adapters will be connected later.
    The hunter currently creates a deterministic investigation case
    without inventing blockchain observations.
    """

    def start_case(
        self,
        seed: str,
        network: str,
    ) -> ScamCase:

        return ScamCase(
            case_id=make_case_id(seed, network),
            seed=seed,
            network=network,
        )

    def analyze_seed(
        self,
        seed: str,
        network: str,
    ) -> Dict[str, Any]:

        case = self.start_case(seed, network)

        return {
            "case": case,
            "next_stage": "transaction_tracing",
            "observations": [],
            "status": "READY_FOR_TRACING",
        }
