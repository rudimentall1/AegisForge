import os
from dataclasses import dataclass


@dataclass(frozen=True)
class ChainConfig:
    name: str
    chain_id: int
    rpc_url: str = ""
    explorer_api_key: str = ""


def load_chain_config(
    name: str = "ethereum",
) -> ChainConfig:

    name = name.lower()

    configs = {
        "ethereum": ChainConfig(
            name="ethereum",
            chain_id=1,
            rpc_url=os.getenv(
                "ETHEREUM_RPC_URL",
                "",
            ),
            explorer_api_key=os.getenv(
                "ETHERSCAN_API_KEY",
                "",
            ),
        ),
        "base": ChainConfig(
            name="base",
            chain_id=8453,
            rpc_url=os.getenv(
                "BASE_RPC_URL",
                "",
            ),
            explorer_api_key=os.getenv(
                "ETHERSCAN_API_KEY",
                "",
            ),
        ),
        "arbitrum": ChainConfig(
            name="arbitrum",
            chain_id=42161,
            rpc_url=os.getenv(
                "ARBITRUM_RPC_URL",
                "",
            ),
            explorer_api_key=os.getenv(
                "ETHERSCAN_API_KEY",
                "",
            ),
        ),
    }

    if name not in configs:
        raise ValueError(
            f"Unsupported network: {name}"
        )

    return configs[name]
