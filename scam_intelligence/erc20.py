from typing import List

from .rpc import EvmRpcProvider
from .schemas import Transaction


# keccak256("Transfer(address,address,uint256)")
TRANSFER_TOPIC = (
    "0xddf252ad1be2c89b69c2b068fc378daa"
    "952ba7f163c4a11628f55a4df523b3ef"
)


def _topic_address(topic: str) -> str:
    """
    Convert a 32-byte indexed ABI address topic
    into a normal 20-byte hex address.
    """

    return "0x" + topic[-40:].lower()


class ERC20TransferCollector:
    """
    Collects ERC-20 Transfer events involving one address.

    Uses eth_getLogs, so no explorer API key is required.

    The collector is read-only.
    """

    def __init__(
        self,
        rpc: EvmRpcProvider,
        chunk_size: int = 10_000,
    ):
        self.rpc = rpc
        self.chunk_size = max(
            1,
            chunk_size,
        )

    def _query(
        self,
        address: str,
        from_block: int,
        to_block: int,
    ) -> List[dict]:

        normalized = address.lower()

        padded = (
            "0x"
            + normalized[2:].rjust(64, "0")
        )

        # topic[1] = from
        logs_from = self.rpc.get_logs(
            from_block,
            to_block,
            topics=[
                TRANSFER_TOPIC,
                padded,
            ],
        )

        # topic[2] = to
        logs_to = self.rpc.get_logs(
            from_block,
            to_block,
            topics=[
                TRANSFER_TOPIC,
                None,
                padded,
            ],
        )

        # Deduplicate logs because some providers
        # may return overlapping results.
        seen = set()
        result = []

        for log in logs_from + logs_to:
            key = (
                log.get("transactionHash"),
                log.get("logIndex"),
            )

            if key in seen:
                continue

            seen.add(key)
            result.append(log)

        return result

    def transfers(
        self,
        address: str,
        from_block: int,
        to_block: int,
    ) -> List[Transaction]:

        if not address.startswith("0x"):
            raise ValueError(
                "Address must start with 0x"
            )

        if len(address) != 42:
            raise ValueError(
                "Invalid EVM address length"
            )

        if from_block > to_block:
            return []

        transfers = []

        current = from_block

        while current <= to_block:
            chunk_end = min(
                current + self.chunk_size - 1,
                to_block,
            )

            logs = self._query(
                address,
                current,
                chunk_end,
            )

            for log in logs:
                topics = log.get(
                    "topics",
                    [],
                )

                if len(topics) < 3:
                    continue

                sender = _topic_address(
                    topics[1]
                )

                recipient = _topic_address(
                    topics[2]
                )

                raw_value = log.get(
                    "data",
                    "0x0",
                )

                try:
                    value = str(
                        int(raw_value, 16)
                    )
                except ValueError:
                    value = "0"

                block_number = int(
                    log.get(
                        "blockNumber",
                        "0x0",
                    ),
                    16,
                )

                transfers.append(
                    Transaction(
                        tx_hash=log.get(
                            "transactionHash",
                            "",
                        ),
                        network=self.rpc.network,
                        from_address=sender,
                        to_address=recipient,
                        value=value,
                        token=log.get(
                            "address",
                            "",
                        ).lower(),
                        block_number=block_number,
                        timestamp=0,
                        success=True,
                        metadata={
                            "type": "ERC20_TRANSFER",
                            "token_contract": log.get(
                                "address",
                                "",
                            ).lower(),
                            "log_index": log.get(
                                "logIndex"
                            ),
                            "transaction_index": log.get(
                                "transactionIndex"
                            ),
                        },
                    )
                )

            current = chunk_end + 1

        return sorted(
            transfers,
            key=lambda tx: (
                tx.block_number,
                tx.metadata.get(
                    "log_index",
                    "0x0",
                ),
            ),
        )
