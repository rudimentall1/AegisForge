import hashlib
import json
from typing import Any, Dict

from .schemas import ScamCase


def make_case_id(seed: str, network: str) -> str:
    digest = hashlib.sha256(
        f"{network}:{seed}".encode()
    ).hexdigest()[:12]

    return f"CASE-AF-{digest}"


def case_to_dict(case: ScamCase) -> Dict[str, Any]:
    return {
        "case_id": case.case_id,
        "seed": case.seed,
        "network": case.network,
        "classification": case.classification,
        "confidence": case.confidence,
        "evidence": [
            vars(item)
            for item in case.evidence
        ],
        "transactions": [
            vars(item)
            for item in case.transactions
        ],
        "flows": [
            vars(item)
            for item in case.flows
        ],
        "clusters": [
            vars(item)
            for item in case.clusters
        ],
        "linked_addresses": case.linked_addresses,
        "linked_contracts": case.linked_contracts,
        "attributions": [
            vars(item)
            for item in case.attributions
        ],
        "entity_links": [
            vars(item)
            for item in case.entity_links
        ],
        "status": case.status,
    }


def case_to_json(case: ScamCase) -> str:
    return json.dumps(
        case_to_dict(case),
        indent=2,
        ensure_ascii=False,
    )
