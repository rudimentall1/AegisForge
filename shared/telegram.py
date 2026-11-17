import os
import sys
import logging

# Добавляем корень проекта в path для корректного импорта модулей
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

TELEGRAM_BOT_TOKEN = "8426799102:AAEAMz0lWfvyQrpcE1hkf9uINONt40UTEB0"
TELEGRAM_CHAT_ID = "659223890"

def send_telegram_alert(message: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logging.warning("[TELEGRAM] Bot token or chat ID not configured.")
        return False
    
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": f"🚨 **AegisForge Security Alert** 🚨\n\n{message}",
        "parse_mode": "Markdown"
    }
    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            logging.info("[TELEGRAM] Alert sent successfully!")
            return True
        else:
            logging.error(f"[TELEGRAM ERROR] Failed to send: {response.text}")
            return False
    except Exception as e:
        logging.error(f"[TELEGRAM EXCEPTION] {e}")
        return False

if __name__ == "__main__":
    send_telegram_alert("Test alert from AegisForge autonomous farm! 🚀")
