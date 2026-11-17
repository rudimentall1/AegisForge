import sqlite3
import time
import requests
import os
from datetime import datetime

DB_PATH = "/opt/agent-farm/shared/tasks.db"
TARGETS = [
    {"name": "NEAR AI Agent Market", "url": "https://market.near.ai/api/v1/agents", "chain": "near"},
    {"name": "Olas Registry", "url": "https://registry.olas.network/api/v1/services", "chain": "ethereum"},
    {"name": "Virtuals Protocol", "url": "https://api.virtuals.io/api/agents", "chain": "base"}
]

def poll_markets():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    for target in TARGETS:
        try:
            response = requests.get(target["url"], timeout=10)
            if response.status_code == 200:
                print(f"[{datetime.now()}] Successfully polled {target['name']}")
                desc = f"Scraped from {target['name']} ({target['url']})"
                # Используем существующие поля таблицы queue: description, chain, status
                cursor.execute(
                    "INSERT INTO queue (description, chain, status) VALUES (?, ?, ?)", 
                    (desc, target["chain"], "pending")
                )
                conn.commit()
            else:
                print(f"[{datetime.now()}] Warning: {target['name']} returned status {response.status_code}")
        except Exception as e:
            print(f"[{datetime.now()}] Error polling {target['name']}: {e}")
            
    conn.close()

if __name__ == "__main__":
    print("[+] Market Watcher Scraper started. Monitoring agent marketplaces 24/7...")
    while True:
        poll_markets()
        time.sleep(300)
