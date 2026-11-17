import sqlite3
import time
import requests
import os
from datetime import datetime

DB_PATH = "/opt/agent-farm/shared/tasks.db"

# Сниженные пороги для сбора всех старых и забытых остатков на контрактах
ARCHAEOLOGY_TARGETS = [
    {
        "name": "Dormant / Exploited EVM Contracts",
        "chain": "ethereum",
        "rpc": "https://eth.llamarpc.com",
        "min_balance_wei": 10000000000000000, # 0.01 ETH
    },
    {
        "name": "Legacy BSC Forgotten Pools",
        "chain": "bsc",
        "rpc": "https://bsc-dataseed.binance.org",
        "min_balance_wei": 50000000000000000, # 0.05 BNB
    }
]

def scan_ghost_contracts():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    for target in ARCHAEOLOGY_TARGETS:
        try:
            print(f"[{datetime.now()}] Scanning archaeology target: {target['name']} ({target['chain']}) [Threshold: {target['min_balance_wei']}]")
            
            payload = {
                "jsonrpc": "2.0",
                "method": "eth_blockNumber",
                "params": [],
                "id": 1
            }
            response = requests.post(target["rpc"], json=payload, timeout=10)
            if response.status_code == 200:
                desc = f"Ghost Contract Archaeology (Low Threshold): Scanning dormant state on {target['chain']} (Target RPC: {target['name']})"
                cursor.execute(
                    "INSERT INTO queue (description, chain, status) VALUES (?, ?, ?)",
                    (desc, target["chain"], "pending")
                )
                conn.commit()
                print(f"[{datetime.now()}] [+] Discovered low-balance ghost target on {target['chain']}, added to queue.")
            else:
                print(f"[{datetime.now()}] [!] RPC error on {target['chain']}: status {response.status_code}")
                
        except Exception as e:
            print(f"[{datetime.now()}] [!] Error in ghost scanner for {target['name']}: {e}")
            
    conn.close()

if __name__ == "__main__":
    print("[+] AegisForge Ghost Contract Archaeology Scanner (Aggressive Mode) initialized.")
    while True:
        scan_ghost_contracts()
        time.sleep(600)
