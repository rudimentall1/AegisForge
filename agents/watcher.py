import os
import time
import sqlite3
import logging
from web3 import Web3

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [WATCHER] %(message)s")

RPC_URL = os.getenv("BASE_RPC_URL", "https://mainnet.base.org")
w3 = Web3(Web3.HTTPProvider(RPC_URL))

def add_task_to_queue(description: str, case_id: str):
    conn = sqlite3.connect('shared/tasks.db')
    cursor = conn.cursor()
    # Проверяем, нет ли уже такого кейса в pending
    cursor.execute("SELECT id FROM queue WHERE research_case_id = ? AND status = 'pending'", (case_id,))
    if not cursor.fetchone():
        cursor.execute('''
            INSERT INTO queue (description, research_case_id, status)
            VALUES (?, ?, 'pending')
        ''', (description, case_id))
        conn.commit()
        logging.info(f"New automated task added: {case_id} | {description}")
    conn.close()

def run_watcher():
    logging.info("Blockchain monitoring watcher started...")
    last_block = w3.eth.block_number
    
    while True:
        try:
            current_block = w3.eth.block_number
            if current_block > last_block:
                block = w3.eth.get_block(current_block, full_transactions=True)
                for tx in block.transactions:
                    # Если транзакция создает контракт (to is None)
                    if tx.get('to') is None and tx.get('creates'):
                        contract_address = tx['creates']
                        case_id = f"base:{contract_address}"
                        add_task_to_queue(
                            description=f"vulnerability scan for newly deployed contract in block {current_block}",
                            case_id=case_id
                        )
                last_block = current_block
            time.sleep(5)
        except Exception as e:
            logging.error(f"Watcher error: {e}")
            time.sleep(10)

if __name__ == "__main__":
    run_watcher()
