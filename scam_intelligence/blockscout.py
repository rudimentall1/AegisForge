import json
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Any, Dict, List, Optional

from .schemas import Transaction


class BlockscoutCollector:
    """
    Read-only Blockscout API collector.

    Discovery layer:
    - native transactions
    - ERC-20 transfers

    RPC remains the independent verification layer.
    """

    BASE_URLS = {
        "ethereum": "https://eth.blockscout.com/api/v2",
        "base": "https://base.blockscout.com/api/v2",
        "arbitrum": "https://arbitrum.blockscout.com/api/v2",
    }

    def __init__(self, network: str, timeout: int = 20):
        network = network.lower()

        if network not in self.BASE_URLS:
            raise ValueError(
                f"Unsupported Blockscout network: {network}"
            )

        self.network = network
        self.base_url = self.BASE_URLS[network]
        self.timeout = timeout

    def _get(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:

        params = params or {}

        query = urllib.parse.urlencode(
            {
                key: value
                for key, value in params.items()
                if value is not None
            }
        )

        url = f"{self.base_url}{path}"

        if query:
            url = f"{url}?{query}"

        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
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

    @staticmethod
    def _timestamp(value: Optional[str]) -> int:
        if not value:
            return 0

        try:
            normalized = value.replace(
                "Z",
                "+00:00",
            )

            return int(
                datetime.fromisoformat(
                    normalized
                ).timestamp()
            )

        except (ValueError, TypeError):
            return 0

    def transactions(
        self,
        address: str,
        limit: int = 50,
    ) -> List[Transaction]:

        data = self._get(
            f"/addresses/{address}/transactions"
        )

        items = data.get("items", [])

        result = []

        for item in items[:limit]:

            sender = (
                item.get("from") or {}
            ).get("hash", address)

            recipient = (
                item.get("to") or {}
            ).get("hash", "")

            result.append(
                Transaction(
                    tx_hash=item.get(
                        "hash",
                        "",
                    ),
                    network=self.network,
                    from_address=sender.lower(),
                    to_address=recipient.lower(),
                    value=str(
                        item.get(
                            "value",
                            "0",
                        )
                    ),
                    token="NATIVE",
                    block_number=int(
                        item.get(
                            "block_number",
                            0,
                        ) or 0
                    ),
                    timestamp=self._timestamp(
                        item.get(
                            "timestamp"
                        )
                    ),
                    success=(
                        item.get(
                            "status",
                            "ok",
                        ) == "ok"
                    ),
                    metadata={
                        "method": item.get(
                            "method"
                        ),
                        "fee": item.get(
                            "fee"
                        ) or {},
                        "transaction_type": item.get(
                            "type"
                        ),
                    },
                )
            )

        return result

    def token_transfers(
        self,
        address: str,
        limit: int = 50,
    ) -> List[Transaction]:

        data = self._get(
            f"/addresses/{address}/token-transfers",
            {
                "type": "ERC-20",
            },
        )

        items = data.get("items", [])

        result = []

        for item in items[:limit]:

            sender = (
                item.get("from") or {}
            ).get("hash", "")

            recipient = (
                item.get("to") or {}
            ).get("hash", "")

            token = (
                item.get("token") or {}
            )

            total = (
                item.get("total") or {}
            )

            result.append(
                Transaction(
                    tx_hash=item.get(
                        "transaction_hash",
                        "",
                    ),
                    network=self.network,
                    from_address=sender.lower(),
                    to_address=recipient.lower(),
                    value=str(
                        total.get(
                            "value",
                            "0",
                        )
                    ),
                    token=(
                        token.get(
                            "address_hash",
                            "",
                        ).lower()
                    ),
                    block_number=int(
                        item.get(
                            "block_number",
                            0,
                        ) or 0
                    ),
                    timestamp=self._timestamp(
                        item.get(
                            "timestamp"
                        )
                    ),
                    success=True,
                    metadata={
                        "type": "ERC20_TRANSFER",
                        "token_symbol": token.get(
                            "symbol"
                        ),
                        "token_name": token.get(
                            "name"
                        ),
                        "decimals": token.get(
                            "decimals"
                        ),
                        "token_type": token.get(
                            "type"
                        ),
                        "method": item.get(
                            "method"
                        ),
                        "log_index": item.get(
                            "log_index"
                        ),
                    },
                )
            )

        return result

    def address_activity(
        self,
        address: str,
        limit: int = 50,
    ) -> Dict[str, List[Transaction]]:

        return {
            "native": self.transactions(
                address,
                limit=limit,
            ),
            "erc20": self.token_transfers(
                address,
                limit=limit,
            ),
        }
