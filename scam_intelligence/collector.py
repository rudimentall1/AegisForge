import json
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from .schemas import Transaction


class BlockchainCollector(ABC):
    """Read-only interface for blockchain transaction collectors."""

    @abstractmethod
    def transactions(
        self,
        address: str,
        limit: int = 100,
    ) -> List[Transaction]:
        raise NotImplementedError


class JsonRpcClient:
    """Minimal dependency-free JSON-RPC client."""

    def __init__(self, rpc_url: str, timeout: int = 20):
        self.rpc_url = rpc_url
        self.timeout = timeout
        self._request_id = 0

    def call(
        self,
        method: str,
        params: Optional[list] = None,
    ) -> Any:
        self._request_id += 1

        payload = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
            "params": params or [],
        }

        request = urllib.request.Request(
            self.rpc_url,
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "AegisForge/1.0",
            },
            method="POST",
        )

        with urllib.request.urlopen(
            request,
            timeout=self.timeout,
        ) as response:
            data = json.loads(response.read().decode())

        if "error" in data:
            raise RuntimeError(
                f"RPC error: {data['error']}"
            )

        return data.get("result")


class EtherscanV2Collector(BlockchainCollector):
    """
    Etherscan-compatible V2 transaction collector.

    Requires an API key.

    The collector only reads public blockchain data and converts
    provider responses into AegisForge Transaction objects.
    """

    BASE_URL = "https://api.etherscan.io/v2/api"

    def __init__(
        self,
        api_key: str,
        chain_id: int = 1,
        timeout: int = 20,
    ):
        if not api_key:
            raise ValueError("Etherscan API key is required")

        self.api_key = api_key
        self.chain_id = chain_id
        self.timeout = timeout

    def _request(
        self,
        address: str,
        limit: int,
    ) -> Dict[str, Any]:

        params = urllib.parse.urlencode({
            "chainid": self.chain_id,
            "module": "account",
            "action": "txlist",
            "address": address,
            "startblock": 0,
            "endblock": 99999999,
            "page": 1,
            "offset": limit,
            "sort": "desc",
            "apikey": self.api_key,
        })

        url = f"{self.BASE_URL}?{params}"

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "AegisForge/1.0",
            },
        )

        with urllib.request.urlopen(
            request,
            timeout=self.timeout,
        ) as response:
            return json.loads(
                response.read().decode()
            )

    def transactions(
        self,
        address: str,
        limit: int = 100,
    ) -> List[Transaction]:

        data = self._request(address, limit)

        result = data.get("result", [])

        if not isinstance(result, list):
            raise RuntimeError(
                f"Etherscan API error: {result}"
            )

        transactions = []

        for item in result:
            transactions.append(
                Transaction(
                    tx_hash=item.get("hash", ""),
                    network=str(self.chain_id),
                    from_address=item.get("from", ""),
                    to_address=item.get("to", ""),
                    value=item.get("value", "0"),
                    token="NATIVE",
                    block_number=int(
                        item.get("blockNumber", 0) or 0
                    ),
                    timestamp=int(
                        item.get("timeStamp", 0) or 0
                    ),
                    success=item.get(
                        "isError", "0"
                    ) == "0",
                    metadata={
                        "nonce": item.get("nonce"),
                        "gas": item.get("gas"),
                        "gas_price": item.get("gasPrice"),
                        "gas_used": item.get("gasUsed"),
                        "input": item.get("input"),
                        "contract_address": item.get(
                            "contractAddress"
                        ),
                    },
                )
            )

        return transactions


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
