import os, time, logging, threading, requests
from agents.config import RESCUE_WALLET_ADDRESS
from agents.rescue import check_contract_balance

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("AuditBot")


def send(chat_id, text):
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        logger.warning("Telegram bot token is not configured")
        return False
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        # Отправляем чистый текст без parse_mode, чтобы исключить любые ошибки парсинга
        resp = requests.post(url, json={"chat_id": chat_id, "text": text}, timeout=5)
        if not resp.json().get("ok"):
            logger.error(f"Telegram API Error: {resp.text}")
            return False
        return True
    except Exception as e:
        logger.error(f"Send exception: {e}")

def audit_task(chat_id, addr, chain, user):
    try:
        logger.info(f"Checking {addr} on {chain}...")
        bal = check_contract_balance(addr, chain)
        rep = f"📊 Результат аудита AegisForge\n\n📍 Адрес: {addr}\n🌐 Сеть: {chain}\n💰 Баланс: {bal} ETH\n\n⚠️ Анализ завершен. Контакт: @{user}"
        send(chat_id, rep)
        logger.info("Audit report sent successfully!")
    except Exception as e:
        logger.error(f"Audit task error: {e}")
        send(chat_id, f"❌ Ошибка выполнения: {e}")

def main():
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        logger.error("Telegram bot token is not configured; polling will not start")
        return
    logger.info("Bot started polling...")
    offset = 0
    while True:
        try:
            r = requests.get(f"https://api.telegram.org/bot{token}/getUpdates?offset={offset}&timeout=30", timeout=35).json()
            if not r.get("ok"):
                time.sleep(3)
                continue
            for res in r.get("result", []):
                offset = res["update_id"] + 1
                msg = res.get("message")
                if not msg or "text" not in msg:
                    continue
                cid, txt, usr = msg["chat"]["id"], msg["text"].strip(), msg["from"].get("username", "unknown")
                
                if txt.startswith("/start"):
                    send(cid, "🛡 AegisForge Audit Bot\n\nИспользуй:\n/audit <адрес> <сеть> — экспресс-проверка\n/pricing — тарифы")
                elif txt.startswith("/pricing"):
                    send(cid, f"💎 Тарифы\nЭкспресс: Бесплатно\nFull Audit: 0.05 ETH\nRescue: 10-20%\nКошелек: {RESCUE_WALLET_ADDRESS}")
                elif txt.startswith("/audit"):
                    p = txt.split()
                    if len(p) < 2:
                        send(cid, "❌ Пример: /audit 0x123... arbitrum")
                        continue
                    addr, chain = p[1], (p[2] if len(p) > 2 else "arbitrum")
                    send(cid, f"🔍 Проверяю {addr} в сети {chain}...")
                    threading.Thread(target=audit_task, args=(cid, addr, chain, usr), daemon=True).start()
        except Exception as e:
            logger.error(f"Polling error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()
