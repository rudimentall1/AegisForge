from typing import Any, Dict

from .blockscout import BlockscoutCollector
from .config import load_chain_config
from .investigation import ScamInvestigator
from .rpc import EvmRpcProvider


def run_investigation(
    address: str,
    network: str = "ethereum",
    limit: int = 100,
    depth: int = 3,
) -> Dict[str, Any]:

    config = load_chain_config(network)

    # Blockscout is the discovery/indexing layer.
    collector = BlockscoutCollector(network=network)

    # RPC is the independent verification layer.
    rpc = None
    if config.rpc_url:
        rpc = EvmRpcProvider(
            rpc_url=config.rpc_url,
            network=network,
        )

    investigator = ScamInvestigator(
        collector=collector,
        rpc=rpc,
    )

    return investigator.investigate(
        seed=address,
        network=network,
        limit=limit,
        depth=depth,
    )
