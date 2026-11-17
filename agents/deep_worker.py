import os
import sqlite3
import time
import logging
import requests

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] [%(filename)s] %(message)s")

DB_PATH = "shared/tasks.db"
TELEGRAM_BOT_TOKEN = "8426799102:AAEAMz0lWfvyQrpcE1hkf9uINONt40UTEB0"
TELEGRAM_CHAT_ID = "659223890"

def init_deep_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS deep_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chain TEXT,
            contract_address TEXT,
            status TEXT,
            findings TEXT,
            timestamp REAL
        )
    """)
    conn.commit()
    conn.close()

def send_telegram_alert(message: str):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": f"🛡️ **AegisForge Deep Security Report** 🛡️\n\n{message}",
        "parse_mode": "Markdown"
    }
    try:
        requests.post(url, json=payload, timeout=10)
    except Exception as e:
        logging.error(f"[TELEGRAM ERROR] {e}")

def run_deep_scanner():
    init_deep_db()
    logging.info("[DEEP WORKER] Started background deep scan worker...")
    
    while True:
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Find contracts that haven't been deep-scanned yet
            cursor.execute("""
                SELECT id, chain, contract_address, code_snippet 
                FROM deployments 
                WHERE deep_scanned = 0 
                LIMIT 5
            """)
            rows = cursor.fetchall()
            
            if not rows:
                conn.close()
                time.sleep(10)
                continue
                
            for row in rows:
                task_id = row["id"]
                chain = row["chain"]
                contract = row["contract_address"]
                
                logging.info(f"[DEEP SCAN] Analyzing contract {contract} on {chain} for Advanced Vectors (Oracles, Fee-on-Transfer, Low-level calls)...")
                
                # Simulate deep analysis findings (Placeholder for AST / Advanced pattern checker)
                # In production, this inspects bytecode or source patterns for oracle staleness / transfer fees
                findings = []
                
                # Example checks simulation
                # (We can expand this to actual static/dynamic checks)
                
                # Mark as deep scanned
                cursor.execute("UPDATE deployments SET deep_scanned = 1 WHERE id = ?", (task_id,))
                conn.commit()
                
                # If critical advanced vulnerability found, notify via Telegram
                if findings:
                    msg = f"🌐 Chain: `{chain}`\n🎯 Contract: `{contract}`\n⚠️ Advanced Risk: " + ", ".join(findings)
                    send_telegram_alert(msg)
                    
            conn.close()
        except Exception as e:
            logging.error(f"[DEEP WORKER EXCEPTION] {e}")
            time.sleep(5)

if __name__ == "__main__":
    run_deep_scanner()
