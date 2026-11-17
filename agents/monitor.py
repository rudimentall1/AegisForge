import os
import time
import logging
import requests
from web3 import Web3
from agents.worker import process_target_contract

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

RPC_URL = os.getenv("EVM_RPC_URL", "https://arb1.arbitrum.io/rpc")
w3 = Web3(Web3.HTTPProvider(RPC_URL))

def scan_latest_blocks():
    logging.info(f"Starting AegisForge Blockchain Monitor on RPC: {RPC_URL}")
    
    if not w3.is_connected():
        logging.error("Failed to connect to EVM RPC node!")
        return

    last_processed_block = w3.eth.block_number - 1

    while True:
        try:
            current_block = w3.eth.block_number
            if current_block > last_processed_block:
                block = w3.eth.get_block(current_block, full_transactions=True)
                logging.info(f"Scanning block #{current_block} ({len(block.transactions)} txs)...")

                for tx in block.transactions:
                    if tx.to is None and tx.input and len(tx.input) > 10:
                        receipt = w3.eth.get_transaction_receipt(tx.hash)
                        contract_address = receipt.contractAddress if receipt else None
                        if contract_address:
                            logging.info(f"[!] New contract deployed: {contract_address}")
                            contract_source = f"// Deployed via tx: {tx.hash.hex()}\n// Bytecode: {tx.input[:200]}..."
                            process_target_contract(contract_address, contract_source)

                last_processed_block = current_block

            time.sleep(5)
        except Exception as e:
            logging.error(f"Error in monitor loop: {e}")
            time.sleep(10)

if __name__ == "__main__":
    scan_latest_blocks()
