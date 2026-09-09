from typing import Any, Dict, List, Set

from .attribution import AttributionEngine
from .cluster import AddressClusterer
from .evidence import EvidenceEngine
from .entity_linker import EntityLinker
from .schemas import Evidence, Transaction
from .tracer import TransactionTracer


class ScamInvestigator:

    def __init__(self, collector, rpc=None):
        self.collector = collector
        self.rpc = rpc

        self.tracer = TransactionTracer()
        self.clusterer = AddressClusterer()
        self.entity_linker = EntityLinker()
        self.evidence_engine = EvidenceEngine()
        self.attribution = AttributionEngine()

    @staticmethod
    def _erc20_transfer_matches(tx: Transaction, receipt: Dict[str, Any]) -> Dict[str, Any]:
        transfer_topic = (
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        )

        def normalize_address(value: Any) -> str:
            value = str(value or "").lower()
            if value.startswith("0x"):
                return value
            return "0x" + value

        def normalize_int(value: Any) -> int:
            if isinstance(value, int):
                return value
            if isinstance(value, str):
                value = value.strip()
                if not value:
                    return 0
                return int(value, 16) if value.startswith("0x") else int(value)
            return int(value)

        expected_to = normalize_address(tx.to_address)
        expected_token = normalize_address(tx.token)
        expected_value = normalize_int(tx.value)
        expected_log_index = tx.metadata.get("log_index")

        for log in receipt.get("logs", []) or []:
            topics = log.get("topics") or []

            if len(topics) < 3:
                continue

            if str(topics[0]).lower() != transfer_topic:
                continue

            if expected_log_index is not None:
                try:
                    rpc_log_index = normalize_int(log.get("logIndex"))
                    indexed_log_index = normalize_int(expected_log_index)
                except (TypeError, ValueError):
                    continue

                if rpc_log_index != indexed_log_index:
                    continue

            token_address = normalize_address(log.get("address"))

            if token_address != expected_token:
                continue

            from_address = normalize_address(topics[1][-40:])
            to_address = normalize_address(topics[2][-40:])

            try:
                transfer_value = normalize_int(log.get("data", "0x0"))
            except (TypeError, ValueError):
                continue

            if to_address != expected_to:
                continue

            if transfer_value != expected_value:
                continue

            return {
                "matched": True,
                "token": token_address,
                "from": from_address,
                "to": to_address,
                "value": str(transfer_value),
                "log_index": normalize_int(log.get("logIndex")),
            }

        return {
            "matched": False,
            "token": expected_token,
            "from": "",
            "to": expected_to,
            "value": str(expected_value),
            "log_index": expected_log_index,
        }

    def _verify_transaction(
        self,
        tx: Transaction,
    ) -> Transaction:

        if not self.rpc:
            return tx

        try:
            verified = self.rpc.get_transaction(tx.tx_hash)

            if not verified:
                tx.metadata["rpc_verified"] = False
                tx.metadata["rpc_verification_error"] = (
                    "transaction_not_found"
                )
                return tx

            is_erc20 = (
                tx.metadata.get("type")
                == "ERC20_TRANSFER"
            )

            if is_erc20:
                receipt = self.rpc.get_receipt(
                    tx.tx_hash
                )

                if not receipt:
                    tx.metadata["rpc_verified"] = False
                    tx.metadata["verification_state"] = "UNVERIFIED"
                    tx.metadata["rpc_verification_error"] = (
                        "receipt_not_found"
                    )
                    return tx

                receipt_status = receipt.get("status")

                tx.metadata["rpc_receipt_status"] = (
                    receipt_status
                )

                tx.metadata["rpc_success"] = (
                    receipt_status == "0x1"
                    if receipt_status is not None
                    else verified.success
                )

                transfer = (
                    self._erc20_transfer_matches(
                        tx,
                        receipt,
                    )
                )

                tx.metadata["rpc_verified"] = (
                    transfer["matched"]
                )

                tx.metadata["rpc_receipt_verified"] = (
                    transfer["matched"]
                )

                tx.metadata["verification_state"] = (
                    "VERIFIED"
                    if transfer["matched"]
                    else "MISMATCH"
                )

                tx.metadata["verified_token"] = (
                    transfer["token"]
                )

                tx.metadata["verified_token_from"] = (
                    transfer["from"]
                )

                tx.metadata["verified_token_to"] = (
                    transfer["to"]
                )

                tx.metadata["verified_token_value"] = (
                    transfer["value"]
                )

                tx.metadata["verified_log_index"] = (
                    transfer["log_index"]
                )

                tx.metadata["verified_transaction_to"] = (
                    verified.to_address
                )

                tx.metadata["verified_native_value"] = (
                    verified.value
                )

                return tx

            matches = (
                verified.from_address.lower()
                == tx.from_address.lower()
                and verified.to_address.lower()
                == tx.to_address.lower()
                and verified.value == tx.value
                and verified.success
            )

            tx.metadata["rpc_verified"] = matches
            tx.metadata["verification_state"] = (
                "VERIFIED"
                if matches
                else "MISMATCH"
            )
            tx.metadata["rpc_block_number"] = (
                verified.block_number
            )
            tx.metadata["rpc_success"] = (
                verified.success
            )
            tx.metadata["verified_from"] = (
                verified.from_address
            )
            tx.metadata["verified_to"] = (
                verified.to_address
            )
            tx.metadata["verified_native_value"] = (
                verified.value
            )

            return tx

        except Exception as exc:
            tx.metadata["rpc_verified"] = False
            tx.metadata["verification_state"] = "ERROR"
            tx.metadata["rpc_verification_error"] = (
                f"{type(exc).__name__}: {exc}"
            )
            return tx

    def _collect_address(
        self,
        address: str,
        limit: int,
    ) -> List[Transaction]:

        if hasattr(self.collector, "collect"):
            return self.collector.collect(
                address,
                limit=limit,
            )

        return self.collector.transactions(
            address,
            limit=limit,
        )

    def investigate(
        self,
        seed: str,
        network: str,
        depth: int = 2,
        limit: int = 50,
    ) -> Dict[str, Any]:

        seed = seed.lower()

        all_transactions: List[Transaction] = []
        seen_tx: Set[str] = set()

        visited_addresses: Set[str] = set()

        address_nodes: Dict[str, Dict[str, Any]] = {
            seed: {
                "address": seed,
                "depth": 0,
                "parent_address": None,
                "discovered_from_tx": None,
            }
        }

        frontier = {seed}

        for current_depth in range(depth + 1):

            if not frontier:
                break

            next_frontier: Set[str] = set()

            for address in frontier:

                address = address.lower()

                if address in visited_addresses:
                    continue

                visited_addresses.add(address)

                transactions = self._collect_address(
                    address,
                    limit,
                )

                for tx in transactions:

                    if not tx.tx_hash:
                        continue

                    tx = self._verify_transaction(tx)

                    tx.metadata["discovery_depth"] = current_depth
                    tx.metadata["discovered_from_address"] = address

                    if tx.tx_hash not in seen_tx:
                        seen_tx.add(tx.tx_hash)
                        all_transactions.append(tx)

                    if not tx.success:
                        continue

                    sender = tx.from_address.lower()
                    recipient = tx.to_address.lower()

                    related = []

                    if sender and sender != address:
                        related.append(sender)

                    if recipient and recipient != address:
                        related.append(recipient)

                    for related_address in related:

                        # Do not create graph nodes beyond the requested
                        # investigation depth. The current address is already
                        # at current_depth, so related addresses belong to
                        # current_depth + 1.
                        if current_depth >= depth:
                            continue

                        if related_address not in address_nodes:
                            address_nodes[related_address] = {
                                "address": related_address,
                                "depth": current_depth + 1,
                                "parent_address": address,
                                "discovered_from_tx": tx.tx_hash,
                            }

                        if related_address not in visited_addresses:
                            next_frontier.add(related_address)

            frontier = next_frontier

        flows = self.tracer.build_flows(
            all_transactions,
            seed,
            max_depth=depth + 1,
        )

        clusters = self.clusterer.cluster_from_flows(
            flows,
            seed,
        )

        entity_links = self.entity_linker.link(
            all_transactions,
            seed=seed,
        )

        evidence: List[Evidence] = []

        verified_count = sum(
            1
            for tx in all_transactions
            if tx.metadata.get("rpc_verified")
        )

        rpc_failed_count = sum(
            1
            for tx in all_transactions
            if tx.metadata.get("rpc_verification_error")
        )

        if all_transactions:
            evidence.append(
                Evidence(
                    evidence_id="TX-DISCOVERY",
                    category="onchain",
                    source=type(self.collector).__name__,
                    subject=seed,
                    observation=(
                        f"Collected {len(all_transactions)} "
                        f"unique transactions across "
                        f"{len(visited_addresses)} "
                        f"visited addresses"
                    ),
                    strength=0.50,
                    verified=verified_count > 0,
                    metadata={
                        "verified_transactions": verified_count,
                        "rpc_verification_failures": rpc_failed_count,
                        "visited_addresses": len(
                            visited_addresses
                        ),
                    },
                )
            )

        if flows:
            evidence.append(
                Evidence(
                    evidence_id="FLOW-ANALYSIS",
                    category="transaction_flow",
                    source="AegisForge.TransactionTracer",
                    subject=seed,
                    observation=(
                        f"Observed {len(flows)} "
                        f"connected transaction flows"
                    ),
                    strength=0.40,
                    verified=True,
                )
            )

        if entity_links:
            evidence.append(
                Evidence(
                    evidence_id="ENTITY-LINKS",
                    category="entity_linking",
                    source="AegisForge.EntityLinker",
                    subject=seed,
                    observation=(
                        f"Generated {len(entity_links)} "
                        f"observable entity relationships"
                    ),
                    strength=0.30,
                    verified=True,
                    metadata={
                        "relation_types": {
                            relation: sum(
                                1
                                for link in entity_links
                                if link.relation_type == relation
                            )
                            for relation in sorted(
                                {
                                    link.relation_type
                                    for link in entity_links
                                }
                            )
                        }
                    },
                )
            )

        case_evidence = self.evidence_engine.collect(
            evidence
        )

        linked_addresses = sorted(
            address_nodes.keys()
        )

        attribution = self.attribution.score(
            "observed-flow-cluster",
            case_evidence,
        )

        return {
            "case_id": f"CASE-AF-{seed[:12]}",
            "seed": seed,
            "network": network,
            "classification": "UNKNOWN",
            "confidence": attribution.confidence,
            "evidence": [
                vars(item)
                for item in case_evidence
            ],
            "transactions": [
                vars(item)
                for item in all_transactions
            ],
            "flows": [
                vars(item)
                for item in flows
            ],
            "clusters": [
                vars(item)
                for item in clusters
            ],
            "entity_links": [
                vars(item)
                for item in entity_links
            ],
            "address_nodes": list(
                address_nodes.values()
            ),
            "linked_addresses": linked_addresses,
            "linked_contracts": [],
            "attributions": [
                vars(attribution)
            ],
            "status": "OPEN",
            "investigation": {
                "depth": depth,
                "visited_addresses": len(
                    visited_addresses
                ),
                "unique_transactions": len(
                    all_transactions
                ),
                "verified_transactions": verified_count,
                "rpc_verification_failures": rpc_failed_count,
            },
        }
