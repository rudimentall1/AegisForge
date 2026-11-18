import logging
import os
import sqlite3
import time

import requests

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
)

DB_PATH = os.getenv("AEGISFORGE_ALERT_DB_PATH", "shared/tasks.db")


def is_duplicate_alert(contract: str, finding_type: str) -> bool:
    """Check whether this contract/finding pair was alerted in the last hour."""
    try:
        os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sent_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    contract TEXT,
                    finding_type TEXT,
                    timestamp REAL
                )
                """
            )
            one_hour_ago = time.time() - 3600
            existing = conn.execute(
                """
                SELECT 1 FROM sent_alerts
                WHERE contract = ? AND finding_type = ? AND timestamp > ?
                LIMIT 1
                """,
                (contract, finding_type, one_hour_ago),
            ).fetchone()
            if existing:
                return True
            conn.execute(
                """
                INSERT INTO sent_alerts (contract, finding_type, timestamp)
                VALUES (?, ?, ?)
                """,
                (contract, finding_type, time.time()),
            )
        return False
    except Exception:
        logging.exception("[DEDUP ERROR]")
        return False


def send_telegram_alert(
    message: str,
    severity: str = "HIGH",
    contract: str | None = None,
    finding_type: str = "GENERAL",
) -> bool:
    """Send a filtered alert using credentials supplied by the runtime environment."""
    normalized_severity = str(severity).upper()
    if normalized_severity in {"INFO", "LOW", "DEBUG"}:
        return False

    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        logging.warning("[TELEGRAM] Alert credentials are not configured")
        return False

    if contract and is_duplicate_alert(contract, finding_type):
        logging.info(
            "[TELEGRAM] Skipped duplicate alert for %s [%s]",
            contract,
            finding_type,
        )
        return False

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": f"🚨 **AegisForge Security Alert [{normalized_severity}]** 🚨\n\n{message}",
        "parse_mode": "Markdown",
    }
    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            logging.info("[TELEGRAM] Filtered alert sent successfully")
            return True
        logging.error("[TELEGRAM ERROR] %s", response.text)
        return False
    except Exception:
        logging.exception("[TELEGRAM EXCEPTION]")
        return False


if __name__ == "__main__":
    send_telegram_alert(
        "Test alert from AegisForge autonomous farm with filtering",
        severity="HIGH",
        contract="0xTest",
        finding_type="TEST",
    )
