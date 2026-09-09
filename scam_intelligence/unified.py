from typing import List

from .blockscout import BlockscoutCollector
from .schemas import Transaction


class UnifiedTransactionCollector:
    """
    Combines native transactions and ERC-20 transfers
    into one normalized activity stream.
    """

    def __init__(
        self,
        blockscout: BlockscoutCollector,
    ):
        self.blockscout = blockscout

    def collect(
        self,
        address: str,
        limit: int = 50,
    ) -> List[Transaction]:

        activity = self.blockscout.address_activity(
            address,
            limit=limit,
        )

        transactions = (
            activity["native"]
            + activity["erc20"]
        )

        seen = set()
        result = []

        for tx in transactions:

            key = (
                tx.tx_hash,
                tx.token,
                tx.metadata.get(
                    "log_index"
                ),
            )

            if key in seen:
                continue

            seen.add(key)
            result.append(tx)

        return sorted(
            result,
            key=lambda tx: (
                tx.block_number,
                tx.timestamp,
            ),
            reverse=True,
        )
