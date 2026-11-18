import os


RESCUE_WALLET_ADDRESS = os.getenv(
    "RESCUE_WALLET_ADDRESS",
    "0x1429906b663608DB6aDeAb8F975B47aFbbe8c68C",
)
# Private key material is never stored in source control or given a default.
RESCUE_PRIVATE_KEY = os.getenv("RESCUE_PRIVATE_KEY", "")
DEFAULT_CHAIN = os.getenv("DEFAULT_CHAIN", "arbitrum").strip().lower()


RPC_ENDPOINTS = {
    "ethereum": os.getenv("ETHEREUM_RPC_URL", "https://cloudflare-eth.com").strip(),
    "arbitrum": os.getenv("ARBITRUM_RPC_URL", "https://arb1.arbitrum.io/rpc").strip(),
    "base": os.getenv("BASE_RPC_URL", "https://mainnet.base.org").strip(),
    "optimism": os.getenv("OPTIMISM_RPC_URL", "https://mainnet.optimism.io").strip(),
    "bsc": os.getenv("BSC_RPC_URL", "https://bsc-dataseed.binance.org/").strip(),
    "robin": os.getenv(
        "ROBIN_RPC_URL",
        "https://rpc.mainnet.chain.robinhood.com",
    ).strip(),
    "arc": os.getenv("ARC_RPC_URL", "https://rpc.mainnet.arc.io").strip(),
    # Retained for compatibility with existing installations and historical tasks.
    "ronin": os.getenv("RONIN_RPC_URL", "https://api.roninchain.com/rpc").strip(),
}


CHAIN_IDS = {
    "ethereum": 1,
    "arbitrum": 42161,
    "base": 8453,
    "optimism": 10,
    "bsc": 56,
    "robin": 4663,
    "arc": 5042,
    "ronin": 2020,
}


EXPLORER_URLS = {
    "ethereum": "https://etherscan.io",
    "arbitrum": "https://arbiscan.io",
    "base": "https://basescan.org",
    "optimism": "https://optimistic.etherscan.io",
    "bsc": "https://bscscan.com",
    "robin": "https://robinhoodchain.blockscout.com",
    "arc": "https://explorer.arc.io",
    "ronin": "https://app.roninchain.com",
}
