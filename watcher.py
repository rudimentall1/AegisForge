import time
import sqlite3
import requests
import logging

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] [%(filename)s] %(message)s")

DB_PATH = "shared/tasks.db"

# Multi-chain RPC lists with fallback rotation
from agents.networks import NETWORKS

# Динамически формируем RPC_POOLS и ожидаемые chain_id из единого реестра
RPC_POOLS = {chain: data["rpc"] for chain, data in NETWORKS.items()}
CHAIN_IDS = {chain: data["chain_id"] for chain, data in NETWORKS.items()}



def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chain TEXT,
            contract_address TEXT,
            status TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def main_watcher():
    init_db()
    logging.info("[WATCHER] Autonomous multi-chain watcher with RPC failover started.")
    
    # Track current active index for each chain
    active_indices = {chain: 0 for chain in RPC_POOLS}
    
    while True:
        for chain, urls in RPC_POOLS.items():
            success = False
            attempts = len(urls)
            
            for _ in range(attempts):
                idx = active_indices[chain]
                rpc_url = urls[idx]
                try:
                    payload = {"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1}
                    res = requests.post(rpc_url, json=payload, timeout=6).json()
                    if "result" in res:
                        block_num = int(res['result'], 16)
                        logging.info(f"[{chain.upper()}] RPC OK (idx {idx}): block {block_num}")
                        success = True
                        break
                    else:
                        logging.warning(f"[{chain.upper()}] RPC idx {idx} invalid result, switching... ({res})")
                except Exception as e:
                    logging.warning(f"[{chain.upper()}] RPC idx {idx} failed ({e}), switching...")
                
                # Switch to next RPC in pool
                active_indices[chain] = (idx + 1) % len(urls)
            
            if not success:
                logging.error(f"[{chain.upper()}] All RPC endpoints in pool are currently unreachable!")
                
        time.sleep(30)

if __name__ == "__main__":
    main_watcher()
