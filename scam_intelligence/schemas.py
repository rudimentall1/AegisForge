from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class Evidence:
    evidence_id: str
    category: str
    source: str
    subject: str
    observation: str
    strength: float = 0.0
    verified: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Attribution:
    entity: str
    confidence: float
    evidence_ids: List[str] = field(default_factory=list)
    status: str = "UNVERIFIED"


@dataclass
class Transaction:
    tx_hash: str
    network: str
    from_address: str
    to_address: str
    value: str = "0"
    token: str = "NATIVE"
    block_number: int = 0
    timestamp: int = 0
    success: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FlowEdge:
    source: str
    target: str
    tx_hash: str
    value: str = "0"
    token: str = "NATIVE"
    depth: int = 0


@dataclass
class AddressCluster:
    cluster_id: str
    addresses: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class EntityLink:
    source: str
    target: str
    relation_type: str
    strength: float
    evidence_ids: List[str] = field(default_factory=list)
    tx_hashes: List[str] = field(default_factory=list)
    reason: str = ""


@dataclass
class ScamCase:
    case_id: str
    seed: str
    network: str
    classification: str = "UNKNOWN"
    confidence: float = 0.0
    evidence: List[Evidence] = field(default_factory=list)
    transactions: List[Transaction] = field(default_factory=list)
    flows: List[FlowEdge] = field(default_factory=list)
    clusters: List[AddressCluster] = field(default_factory=list)
    linked_addresses: List[str] = field(default_factory=list)
    linked_contracts: List[str] = field(default_factory=list)
    attributions: List[Attribution] = field(default_factory=list)
    entity_links: List[EntityLink] = field(default_factory=list)
    status: str = "OPEN"
