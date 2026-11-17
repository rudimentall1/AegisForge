import os
import time
import logging
import requests
from web3 import Web3
from agents.config import RPC_ENDPOINTS
from shared.task_queue import TaskQueue

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("RpcMonitor")

TELEGRAM_TOKEN = "8426799102:AAEAMz0lWfvyQrpcE1hkf9uINONt40UTEB0"
CHAT_ID = "659223890"

def send_telegram_alert(message: str):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        payload = {"chat_id": CHAT_ID, "text": f"🚨 **AegisForge Deploy Watcher**\n\n{message}", "parse_mode": "Markdown"}
        requests.post(url, json=payload, timeout=5)
    except Exception as e:
        logger.error(f"Failed to send Telegram alert: {e}")

def scan_networks_for_deploys():
    queue = TaskQueue()
    logger.info("[MONITOR] Starting block and contract deploy scan across all chains...")
    
    last_blocks = {chain: 0 for chain in RPC_ENDPOINTS.keys()}

    while True:
        for chain, rpc_url in RPC_ENDPOINTS.items():
            try:
                w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 5}))
                if not w3.is_connected():
                    logger.warning(f"RPC for network *{chain}* is disconnected!")
                    continue
                
                latest_block = w3.eth.block_number
                if last_blocks[chain] == 0:
                    last_blocks[chain] = latest_block - 1
                
                if latest_block > last_blocks[chain]:
                    for block_num in range(last_blocks[chain] + 1, latest_block + 1):
                        try:
                            block = w3.eth.get_block(block_num, full_transactions=True)
                            if not block or "transactions" not in block:
                                continue
                            
                            for tx in block["transactions"]:
                                if tx.get("to") is None:
                                    contract_addr = tx.get("creates")
                                    tx_hash = tx.get("hash").hex() if hasattr(tx.get("hash"), "hex") else str(tx.get("hash"))
                                    sender = tx.get("from")
                                    
                                    logger.info(f"[DEPLOY FOUND] Chain: {chain} | Tx: {tx_hash}")
                                    
                                    cursor = queue.db.cursor()
                                    cursor.execute(
                                        "INSERT INTO queue (description, research_case_id, status, created_at) VALUES (?, ?, 'pending', CURRENT_TIMESTAMP)",
                                        (f"Audit new deploy on {chain}: tx {tx_hash}", f"{chain}:{contract_addr or 'unknown'}")
                                    )
                                    queue.db.commit()
                                    cursor.close()
                                    
                                    # Telegram alert on every deploy disabled to avoid spam.
                        except Exception as block_err:
                            logger.error(f"Error reading block {block_num} on {chain}: {block_err}")
                            
                    last_blocks[chain] = latest_block
            except Exception as e:
                logger.error(f"Error scanning network {chain}: {e}")
                
        time.sleep(5)

if __name__ == "__main__":
    scan_networks_for_deploys()
