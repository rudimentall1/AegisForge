from typing import Any, Dict, List, Optional

from .collector import JsonRpcClient
from .schemas import Transaction


class EvmRpcProvider:
    """
    Read-only EVM RPC provider.

    Provides:
    - chain/block information
    - transaction lookup
    - transaction receipt lookup
    - block lookup
    - log queries
    """

    def __init__(
        self,
        rpc_url: str,
        network: str,
        timeout: int = 20,
    ):
        if not rpc_url:
            raise ValueError("RPC URL is required")

        self.network = network
        self.client = JsonRpcClient(
            rpc_url,
            timeout=timeout,
        )

    def health(self) -> Dict[str, Any]:
        chain_id = self.client.call("eth_chainId")
        block_number = self.client.call(
            "eth_blockNumber"
        )

        return {
            "network": self.network,
            "chain_id": int(chain_id, 16),
            "latest_block": int(
                block_number,
                16,
            ),
            "status": "OK",
        }

    def get_transaction(
        self,
        tx_hash: str,
    ) -> Optional[Transaction]:

        raw = self.client.call(
            "eth_getTransactionByHash",
            [tx_hash],
        )

        if not raw:
            return None

        block_number = int(
            raw.get("blockNumber", "0x0"),
            16,
        )

        block = self.get_block(
            block_number,
            full_transactions=False,
        )

        receipt = self.get_receipt(tx_hash)

        return Transaction(
            tx_hash=raw.get("hash", tx_hash),
            network=self.network,
            from_address=raw.get("from", ""),
            to_address=raw.get("to", ""),
            value=str(
                int(
                    raw.get("value", "0x0"),
                    16,
                )
            ),
            token="NATIVE",
            block_number=block_number,
            timestamp=int(
                block.get("timestamp", "0x0"),
                16,
            ),
            success=(
                receipt is None
                or receipt.get("status", "0x1") == "0x1"
            ),
            metadata={
                "nonce": int(
                    raw.get("nonce", "0x0"),
                    16,
                ),
                "gas": int(
                    raw.get("gas", "0x0"),
                    16,
                ),
                "gas_price": int(
                    raw.get(
                        "gasPrice",
                        "0x0",
                    ),
                    16,
                ),
                "input": raw.get("input"),
                "transaction_index": raw.get(
                    "transactionIndex"
                ),
                "receipt_status": (
                    receipt.get("status")
                    if receipt
                    else None
                ),
            },
        )

    def get_receipt(
        self,
        tx_hash: str,
    ) -> Optional[Dict[str, Any]]:

        return self.client.call(
            "eth_getTransactionReceipt",
            [tx_hash],
        )

    def get_block(
        self,
        block_number: int,
        full_transactions: bool = False,
    ) -> Dict[str, Any]:

        block = self.client.call(
            "eth_getBlockByNumber",
            [
                hex(block_number),
                full_transactions,
            ],
        )

        if not block:
            raise ValueError(
                f"Block {block_number} not found"
            )

        return block

    def get_logs(
        self,
        from_block: int,
        to_block: int,
        topics: Optional[List[Any]] = None,
        address: Optional[str] = None,
    ) -> List[Dict[str, Any]]:

        params: Dict[str, Any] = {
            "fromBlock": hex(from_block),
            "toBlock": hex(to_block),
        }

        if topics is not None:
            params["topics"] = topics

        if address:
            params["address"] = address

        return self.client.call(
            "eth_getLogs",
            [params],
        ) or []


class RpcHealthChecker:
    """Small helper for validating an EVM RPC endpoint."""

    def __init__(self, rpc: JsonRpcClient):
        self.rpc = rpc

    def check(self) -> Dict[str, Any]:
        chain_id = self.rpc.call("eth_chainId")
        block_number = self.rpc.call(
            "eth_blockNumber"
        )

        return {
            "chain_id": chain_id,
            "latest_block": int(
                block_number,
                16,
            ),
            "status": "OK",
        }
