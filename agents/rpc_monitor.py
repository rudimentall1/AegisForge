import logging
import time
from datetime import datetime, timezone

from web3 import Web3

from agents.config import CHAIN_IDS, RPC_ENDPOINTS
from shared.discovery import DiscoveryFinding, enqueue_discovery_finding
from agents.evm_traces import extract_internal_creations
from shared.task_queue import TaskQueue

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("RpcMonitor")

POLL_INTERVAL_SECONDS = 5
RPC_TIMEOUT_SECONDS = 5


def _ensure_cursor_table(queue):
    queue.db.execute(
        """
        CREATE TABLE IF NOT EXISTS rpc_monitor_cursors (
            chain TEXT PRIMARY KEY,
            last_processed_block INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    queue.db.commit()


def load_or_initialize_cursor(queue, chain, latest_block):
    """Resume the last durable block, or initialize at the current tip."""
    _ensure_cursor_table(queue)
    row = queue.db.execute(
        "SELECT last_processed_block FROM rpc_monitor_cursors WHERE chain = ?",
        (str(chain),),
    ).fetchone()
    if row is not None:
        return int(row[0])

    # First run starts at the current tip; historical backfill is explicit.
    initial_block = max(int(latest_block) - 1, 0)
    queue.db.execute(
        """
        INSERT OR IGNORE INTO rpc_monitor_cursors
            (chain, last_processed_block, updated_at)
        VALUES (?, ?, ?)
        """,
        (str(chain), initial_block, datetime.now(timezone.utc).isoformat()),
    )
    queue.db.commit()
    row = queue.db.execute(
        "SELECT last_processed_block FROM rpc_monitor_cursors WHERE chain = ?",
        (str(chain),),
    ).fetchone()
    return int(row[0])


def save_cursor(queue, chain, block_number):
    queue.db.execute(
        """
        INSERT INTO rpc_monitor_cursors
            (chain, last_processed_block, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(chain) DO UPDATE SET
            last_processed_block = excluded.last_processed_block,
            updated_at = excluded.updated_at
        """,
        (
            str(chain),
            int(block_number),
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    queue.db.commit()


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
    evidence = {
        "transaction_hash": tx_hash,
        "deployer": sender,
        "receipt_status": receipt.get("status"),
        "block_number": int(block_number),
        "contract_address": Web3.to_checksum_address(contract_address),
    }
    for key in ("deployment_origin", "creation_method", "trace_address"):
        if transaction.get(key) is not None:
            evidence[key] = transaction[key]

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
        evidence=evidence,
        observed_block=int(block_number),
        source="rpc_deployment_monitor",
        transaction_hash=tx_hash,
    )
    return enqueue_discovery_finding(queue, finding)


def record_internal_contract_deployments(
    queue,
    chain,
    block_number,
    trace_response,
    receipt_lookup,
):
    """Enqueue successful internal CREATE/CREATE2 deployments from block traces."""
    creations = extract_internal_creations(trace_response)
    receipt_cache = {}
    results = []

    for creation in creations:
        tx_hash = creation["transaction_hash"]
        if tx_hash not in receipt_cache:
            receipt_cache[tx_hash] = receipt_lookup(tx_hash)
        receipt = receipt_cache[tx_hash]
        if not isinstance(receipt, dict) or receipt.get("status") != 1:
            continue

        transaction = {
            "hash": tx_hash,
            "from": creation["deployer"],
            "deployment_origin": "internal_trace",
            "creation_method": creation["creation_method"],
            "trace_address": creation["trace_address"],
        }
        synthetic_receipt = {
            "status": 1,
            "contractAddress": creation["contract_address"],
        }
        result = record_contract_deployment(
            queue,
            chain,
            block_number,
            transaction,
            synthetic_receipt,
        )
        if result is not None:
            results.append(result)

    return results


def _fetch_block_traces(web3, block_number):
    """Try parity trace_block, then Geth callTracer when the method is unsupported."""
    provider = getattr(web3, "provider", None)
    make_request = getattr(provider, "make_request", None)
    if not callable(make_request):
        return None

    block_tag = hex(int(block_number))
    requests = (
        ("trace_block", [block_tag]),
        ("debug_traceBlockByNumber", [block_tag, {"tracer": "callTracer"}]),
    )
    for method, params in requests:
        try:
            response = make_request(method, params)
        except Exception:
            return None
        if not isinstance(response, dict):
            return None
        if response.get("error") is None:
            if isinstance(response.get("result"), list):
                return response
            continue
        error = response.get("error")
        if isinstance(error, dict) and error.get("code") == -32601:
            continue
        return None
    return None


def scan_networks_for_deploys():
    queue = TaskQueue()
    _ensure_cursor_table(queue)
    logger.info(
        "Starting multi-chain deployment discovery; intake DB is the canonical TaskQueue DB."
    )

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

                actual_chain_id = int(w3.eth.chain_id)
                expected_chain_id = CHAIN_IDS.get(chain)
                if expected_chain_id is not None and actual_chain_id != int(expected_chain_id):
                    logger.error(
                        "RPC chain identity mismatch for %s: expected=%s actual=%s",
                        chain,
                        expected_chain_id,
                        actual_chain_id,
                    )
                    continue

                latest_block = int(w3.eth.block_number)
                last_processed_block = load_or_initialize_cursor(
                    queue,
                    chain,
                    latest_block,
                )
                if latest_block <= last_processed_block:
                    continue

                for block_number in range(last_processed_block + 1, latest_block + 1):
                    block_ok = True
                    try:
                        block = w3.eth.get_block(
                            block_number,
                            full_transactions=True,
                        )
                    except Exception:
                        logger.exception("Error reading block %s on %s", block_number, chain)
                        break

                    for transaction in block.get("transactions", []):
                        if transaction.get("to") is not None:
                            continue

                        tx_hash = _hex_value(transaction.get("hash"))
                        if not tx_hash:
                            logger.error(
                                "Contract creation has no transaction hash: chain=%s block=%s",
                                chain,
                                block_number,
                            )
                            block_ok = False
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
                                    "No successful deployment to enqueue: chain=%s tx=%s",
                                    chain,
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
                            block_ok = False
                            logger.exception(
                                "Failed to ingest deployment %s on %s block %s",
                                tx_hash,
                                chain,
                                block_number,
                            )

                    if block_ok:
                        trace_response = _fetch_block_traces(w3, block_number)
                        if trace_response is not None:
                            try:
                                internal_results = record_internal_contract_deployments(
                                    queue,
                                    chain,
                                    block_number,
                                    trace_response,
                                    w3.eth.get_transaction_receipt,
                                )
                                for task_id, created in internal_results:
                                    logger.info(
                                        "Internal deployment discovery %s: chain=%s task=%s",
                                        "enqueued" if created else "deduplicated",
                                        chain,
                                        task_id,
                                    )
                            except Exception:
                                block_ok = False
                                logger.exception(
                                    "Failed to ingest internal deployments on %s block %s",
                                    chain,
                                    block_number,
                                )

                    if not block_ok:
                        logger.warning(
                            "Cursor not advanced for %s block %s; retrying block",
                            chain,
                            block_number,
                        )
                        break

                    save_cursor(queue, chain, block_number)

            except Exception:
                logger.exception("Error scanning network %s", chain)

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    scan_networks_for_deploys()
