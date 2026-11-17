import os
import requests
import logging
import sqlite3
import time

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s")

TELEGRAM_BOT_TOKEN = "8426799102:AAEAMz0lWfvyQrpcE1hkf9uINONt40UTEB0"
TELEGRAM_CHAT_ID = "659223890"
DB_PATH = "shared/tasks.db"

def is_duplicate_alert(contract: str, finding_type: str) -> bool:
    """Check if we already alerted about this contract & finding within the last hour."""
    try:
        os.makedirs("shared", exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sent_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contract TEXT,
                finding_type TEXT,
                timestamp REAL
            )
        """)
        one_hour_ago = time.time() - 3600
        cursor.execute(
            "SELECT id FROM sent_alerts WHERE contract=? AND finding_type=? AND timestamp > ?",
            (contract, finding_type, one_hour_ago)
        )
        if cursor.fetchone():
            conn.close()
            return True
        
        cursor.execute(
            "INSERT INTO sent_alerts (contract, finding_type, timestamp) VALUES (?, ?, ?)",
            (contract, finding_type, time.time())
        )
        conn.commit()
        conn.close()
        return False
    except Exception as e:
        logging.error(f"[DEDUP ERROR] {e}")
        return False

def send_telegram_alert(message: str, severity: str = "HIGH", contract: str = None, finding_type: str = "GENERAL"):
    # Ignore low/info noise to prevent spam
    if severity.upper() in ["INFO", "LOW", "DEBUG"]:
        return False
        
    # Prevent duplicate alerts for the same contract/finding
    if contract and is_duplicate_alert(contract, finding_type):
        logging.info(f"[TELEGRAM] Skipped duplicate alert for {contract} [{finding_type}]")
        return False

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": f"🚨 **AegisForge Security Alert [{severity.upper()}]** 🚨\n\n{message}",
        "parse_mode": "Markdown"
    }
    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            logging.info("[TELEGRAM] Filtered alert sent successfully!")
            return True
        else:
            logging.error(f"[TELEGRAM ERROR] {response.text}")
            return False
    except Exception as e:
        logging.error(f"[TELEGRAM EXCEPTION] {e}")
        return False

if __name__ == "__main__":
    send_telegram_alert("Test alert from AegisForge autonomous farm with filtering! 🚀", severity="HIGH", contract="0xTest", finding_type="TEST")
