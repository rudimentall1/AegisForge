import os
import time
import sqlite3
import logging
import requests

logger = logging.getLogger("Notifier")

DB_PATH = "shared/tasks.db"

def is_duplicate_alert(contract: str, finding_type: str) -> bool:
    """Check if we already alerted about this contract & vulnerability within the last hour."""
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
        logger.error(f"[DEDUP ERROR] {e}")
        return False

def send_telegram_alert(chain: str, contract: str, vuln_type: str, patch_filename: str):
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        logger.warning("[NOTIFIER] Telegram credentials are not configured")
        return False

    # Prevent duplicate alerts for the same contract & vulnerability type within 1 hour
    if contract and is_duplicate_alert(contract, vuln_type):
        logger.info(f"[NOTIFIER] Skipped duplicate alert for {contract} [{vuln_type}]")
        return False

    message = (
        f"🚨 **AEGISFORGE SECURITY ALERT** 🚨\n\n"
        f"🌐 **Chain:** `{chain}`\n"
        f"🎯 **Contract:** `{contract}`\n"
        f"⚠️ **Vulnerability:** `{vuln_type}`\n"
        f"🛡️ **Generated Patch:** `{patch_filename}`\n\n"
        f"Status: Remediated automatically by AegisForge autonomous worker."
    )

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown"
    }

    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            logger.info("[NOTIFIER] Telegram alert sent successfully!")
            return True
        else:
            logger.error(f"[NOTIFIER ERROR] {response.text}")
            return False
    except Exception as e:
        logger.error(f"[NOTIFIER EXCEPTION] {e}")
        return False

def send_telegram_document(file_path, caption=""):
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        return
    url = f"https://api.telegram.org/bot{token}/sendDocument"
    try:
        with open(file_path, "rb") as doc:
            requests.post(url, data={"chat_id": chat_id, "caption": caption}, files={"document": doc})
    except Exception as e:
        logger.error(f"[NOTIFIER DOC EXCEPTION] {e}")

if __name__ == "__main__":
    send_telegram_alert("optimism", "0xTestContract123456789", "Reentrancy & Unchecked Transfer", "test_patch.sol")
