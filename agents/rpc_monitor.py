import logging
import time

from web3 import Web3

from agents.config import RPC_ENDPOINTS
from shared.discovery import DiscoveryFinding, enqueue_discovery_finding
from shared.task_queue import TaskQueue

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("RpcMonitor")

POLL_INTERVAL_SECONDS = 5
RPC_TIMEOUT_SECONDS = 5


def _hex_value(value):
    if value is None:
        return None
    if hasattr(value, "hex"):
        rendered = value.hex()
        return rendered if rendered.startswith("0x") else "0x" + rendered
    rendered = str(value)
    return rendered if rendered.startswith("0x") else rendered


def record_contract_deployment(queue, chain, block_number, transaction, receipt):
    """Convert a successful contract creation receipt into canonical discovery intake."""
    # Clients may derive contractAddress even for reverted CREATE transactions.
    # A deployment is recorded only when the receipt explicitly reports success.
    if receipt.get("status") != 1:
        return None

    contract_address = receipt.get("contractAddress")
    if not contract_address:
        return None

    tx_hash = _hex_value(transaction.get("hash"))
    if not tx_hash:
        return None

    sender = transaction.get("from")
    finding = DiscoveryFinding(
        chain=str(chain),
        contract_address=Web3.to_checksum_address(contract_address),
        finding_type="contract_deployment",
        severity="info",
        title=f"New contract deployment detected on {chain}",
        description=(
            "A contract creation transaction was observed. Deep Research must "
            "retrieve and inspect deployed runtime bytecode and verified source "
            "when available; deployment alone is not a vulnerability finding."
        ),
        evidence={
            "transaction_hash": tx_hash,
            "deployer": sender,
            "receipt_status": receipt.get("status"),
            "block_number": int(block_number),
            "contract_address": Web3.to_checksum_address(contract_address),
        },
        observed_block=int(block_number),
        source="rpc_deployment_monitor",
        transaction_hash=tx_hash,
    )
    return enqueue_discovery_finding(queue, finding)


def scan_networks_for_deploys():
    queue = TaskQueue()
    logger.info(
        "Starting multi-chain deployment discovery; intake DB is the canonical TaskQueue DB."
    )
    last_blocks = {chain: 0 for chain in RPC_ENDPOINTS}

    while True:
        for chain, rpc_url in RPC_ENDPOINTS.items():
            if not rpc_url:
                logger.warning("RPC endpoint is not configured for %s; skipping", chain)
                continue
            try:
                w3 = Web3(
                    Web3.HTTPProvider(
                        rpc_url,
                        request_kwargs={"timeout": RPC_TIMEOUT_SECONDS},
                    )
                )
                if not w3.is_connected():
                    logger.warning("RPC disconnected for %s", chain)
                    continue

                latest_block = w3.eth.block_number
                if last_blocks[chain] == 0:
                    # Start at the current tip. Historical backfill is a separate,
                    # explicitly bounded operation; do not silently enqueue a backlog.
                    last_blocks[chain] = latest_block - 1

                for block_number in range(last_blocks[chain] + 1, latest_block + 1):
                    try:
                        block = w3.eth.get_block(
                            block_number,
                            full_transactions=True,
                        )
                        for transaction in block.get("transactions", []):
                            if transaction.get("to") is not None:
                                continue

                            tx_hash = _hex_value(transaction.get("hash"))
                            if not tx_hash:
                                logger.warning(
                                    "Skipping contract creation without tx hash on %s block %s",
                                    chain,
                                    block_number,
                                )
                                continue

                            try:
                                receipt = w3.eth.get_transaction_receipt(tx_hash)
                                result = record_contract_deployment(
                                    queue,
                                    chain,
                                    block_number,
                                    transaction,
                                    receipt,
                                )
                                if result is None:
                                    logger.info(
                                        "Contract creation was unsuccessful or had no deployed address: %s",
                                        tx_hash,
                                    )
                                else:
                                    task_id, created = result
                                    logger.info(
                                        "Deployment discovery %s: chain=%s contract=%s task=%s",
                                        "enqueued" if created else "deduplicated",
                                        chain,
                                        receipt.get("contractAddress"),
                                        task_id,
                                    )
                            except Exception:
                                logger.exception(
                                    "Failed to ingest deployment %s on %s",
                                    tx_hash,
                                    chain,
                                )
                    except Exception:
                        logger.exception(
                            "Error reading block %s on %s",
                            block_number,
                            chain,
                        )

                last_blocks[chain] = latest_block
            except Exception:
                logger.exception("Error scanning network %s", chain)

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    scan_networks_for_deploys()
