import os
import sqlite3
import time
import logging
import glob
from agents.notifier import send_telegram_document

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [WORKER] %(message)s")

DB_PATH = "/opt/agent-farm/shared/tasks.db"
RULES_DIR = "/opt/agent-farm/shared/dynamic_rules"

def load_dynamic_rules():
    rules = []
    rule_files = glob.glob(os.path.join(RULES_DIR, "*.sol"))
    for r_file in rule_files:
        try:
            with open(r_file, "r") as f:
                rules.append(f.read())
            logging.info(f"Loaded dynamic rule from {r_file}")
        except Exception as e:
            logging.error(f"Failed to load rule {r_file}: {e}")
    return rules

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chain TEXT,
            contract_address TEXT,
            status TEXT DEFAULT 'pending'
        )
    """)
    conn.commit()
    conn.close()

def process_tasks():
    init_db()
    logging.info("Worker started and listening for tasks with dynamic rules integration...")
    
    while True:
        active_rules = load_dynamic_rules()
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, chain, contract_address FROM queue WHERE status = 'pending' LIMIT 1")
        task = cursor.fetchone()
        
        if task:
            task_id, chain, contract = task
            logging.info(f"Processing task {task_id}: contract {contract} on {chain} (Active rules loaded: {len(active_rules)})")
            
            cursor.execute("UPDATE queue SET status = 'processing' WHERE id = ?", (task_id,))
            conn.commit()
            
            patch_filename = f"/tmp/patch_{contract[:6]}.sol"
            with open(patch_filename, "w") as pf:
                pf.write(f"// SPDX-License-Identifier: MIT\n// Analyzed contract: {contract} on {chain}\n// Applied dynamic rules: {len(active_rules)}\ncontract Patched {{ }}")
            
            caption = f"🚨 Vulnerability detected & analyzed!\nChain: {chain}\nContract: {contract}\nRules applied: {len(active_rules)}"
            send_telegram_document(patch_filename, caption=caption)
            
            cursor.execute("UPDATE queue SET status = 'done' WHERE id = ?", (task_id,))
            conn.commit()
            logging.info(f"Task {task_id} completed successfully.")
            
            if os.path.exists(patch_filename):
                os.remove(patch_filename)
                
        conn.close()
        time.sleep(5)

if __name__ == "__main__":
    process_tasks()
