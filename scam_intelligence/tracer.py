from typing import Iterable, List

from .schemas import FlowEdge, Transaction


class TransactionTracer:
    """
    Builds a transaction flow from normalized transaction records.

    This layer deliberately does not fetch blockchain data itself.
    RPC/explorer adapters can feed normalized Transaction objects into it.
    """

    def build_flows(
        self,
        transactions: Iterable[Transaction],
        seed: str,
        max_depth: int = 3,
    ) -> List[FlowEdge]:

        transactions = list(transactions)

        if max_depth < 1:
            return []

        current = {seed.lower()}
        visited = set()
        flows: List[FlowEdge] = []

        for depth in range(max_depth):
            next_addresses = set()

            for tx in transactions:
                source = tx.from_address.lower()
                target = tx.to_address.lower()

                if source not in current:
                    continue

                if tx.tx_hash in visited:
                    continue

                visited.add(tx.tx_hash)

                flows.append(
                    FlowEdge(
                        source=source,
                        target=target,
                        tx_hash=tx.tx_hash,
                        value=tx.value,
                        token=tx.token,
                        depth=depth,
                    )
                )

                next_addresses.add(target)

            current = next_addresses

            if not current:
                break

        return flows
