import os
import time
import sqlite3
import json
import logging
import requests

from agents.config import RESCUE_WALLET_ADDRESS, RPC_ENDPOINTS

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s")

WALLET_ADDRESS = RESCUE_WALLET_ADDRESS
DB_PATH = "shared/tasks.db"

NETWORKS = {
    chain: RPC_ENDPOINTS[chain]
    for chain in ("ethereum", "arbitrum", "base", "optimism", "bsc", "robin", "arc")
    if RPC_ENDPOINTS.get(chain)
}

MIN_BALANCES = {
    "base": 0.002,
    "arbitrum": 0.002,
    "optimism": 0.002,
    "bsc": 0.01,
    "ethereum": 0.005,
    "arc": 0.01,
    "robin": 0.01
}

def can_send_daily_alert() -> bool:
    try:
        os.makedirs("shared", exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS wallet_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                last_sent REAL
            )
        """)
        cursor.execute("SELECT last_sent FROM wallet_alerts ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        now = time.time()
        if row and (now - row[0] < 24 * 3600):
            conn.close()
            return False
        cursor.execute("INSERT INTO wallet_alerts (last_sent) VALUES (?)", (now,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logging.error(f"[WALLET CHECK ERROR] {e}")
        return True

def send_alert(message: str):
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        logging.warning("[TELEGRAM] Wallet alert credentials are not configured")
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": f"⚠️ **AegisForge Wallet Warning** ⚠️\n\n{message}",
        "parse_mode": "Markdown"
    }
    try:
        response = requests.post(url, json=payload, timeout=10)
        return response.status_code == 200
    except Exception as e:
        logging.error(f"[TELEGRAM ERROR] {e}")
        return False

def check_balances():
    low_balance_warnings = []
    for chain, rpc in NETWORKS.items():
        try:
            payload = {
                "jsonrpc": "2.0",
                "method": "eth_getBalance",
                "params": [WALLET_ADDRESS, "latest"],
                "id": 1
            }
            resp = requests.post(rpc, json=payload, timeout=5)
            if resp.status_code == 200:
                result = resp.json().get("result")
                if result:
                    balance_wei = int(result, 16)
                    balance_eth = balance_wei / 10**18
                    min_required = MIN_BALANCES.get(chain, 0.002)
                    logging.info(f"[{chain.upper()}] Wallet balance: {balance_eth:.4f} (Min: {min_required})")
                    if balance_eth < min_required:
                        low_balance_warnings.append(f"🌐 Chain: `{chain}`\n🎯 Balance: `{balance_eth:.4f}` (Low gas!)")
        except Exception as e:
            logging.error(f"[{chain.upper()} CHECK EXCEPTION] {e}")

    if low_balance_warnings and can_send_daily_alert():
        msg = f"Wallet `{WALLET_ADDRESS}` is running low on gas in the following networks:\n\n" + "\n\n".join(low_balance_warnings)
        send_alert(msg)
        logging.info("[WALLET WATCHER] Low balance daily alert sent to Telegram.")

if __name__ == "__main__":
    check_balances()
