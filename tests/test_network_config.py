from agents.config import CHAIN_IDS, EXPLORER_URLS, RPC_ENDPOINTS


def test_robinhood_chain_uses_its_own_mainnet_identity():
    assert CHAIN_IDS["robin"] == 4663
    assert RPC_ENDPOINTS["robin"] == "https://rpc.mainnet.chain.robinhood.com"
    assert EXPLORER_URLS["robin"] == "https://robinhoodchain.blockscout.com"


def test_arc_uses_arc_mainnet_identity():
    assert CHAIN_IDS["arc"] == 5042
    assert RPC_ENDPOINTS["arc"] == "https://rpc.mainnet.arc.io"
    assert EXPLORER_URLS["arc"] == "https://explorer.arc.io"


def test_bnb_smart_chain_is_configured():
    assert CHAIN_IDS["bsc"] == 56
    assert RPC_ENDPOINTS["bsc"]


def test_wallet_watcher_uses_canonical_multichain_rpc_configuration():
    from agents.config import RESCUE_WALLET_ADDRESS
    from wallet_watcher import NETWORKS, WALLET_ADDRESS

    assert WALLET_ADDRESS == RESCUE_WALLET_ADDRESS
    for chain in ("ethereum", "arbitrum", "base", "optimism", "bsc", "robin", "arc"):
        assert NETWORKS[chain] == RPC_ENDPOINTS[chain]
