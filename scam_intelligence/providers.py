from typing import Any, Dict, Optional

from .collector import BlockchainCollector
from .rpc import EvmRpcProvider


class ProviderManager:
    """
    Coordinates indexed collection and independent RPC verification.

    The indexed collector is responsible for discovery.
    RPC is responsible for verification.
    """

    def __init__(
        self,
        collector: Optional[BlockchainCollector] = None,
        rpc: Optional[EvmRpcProvider] = None,
    ):
        self.collector = collector
        self.rpc = rpc

    def capabilities(self) -> Dict[str, Any]:
        return {
            "indexed_collector": (
                type(self.collector).__name__
                if self.collector
                else None
            ),
            "rpc_provider": (
                type(self.rpc).__name__
                if self.rpc
                else None
            ),
            "historical_address_search": bool(
                self.collector
            ),
            "transaction_verification": bool(
                self.rpc
            ),
        }

    def verify_transaction(
        self,
        tx_hash: str,
    ):
        if not self.rpc:
            raise RuntimeError(
                "RPC provider is not configured"
            )

        return self.rpc.get_transaction(tx_hash)
