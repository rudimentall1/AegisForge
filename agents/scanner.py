import os
import time
import logging
from agents.config import RPC_ENDPOINTS, DEFAULT_CHAIN
from agents.rescue import check_contract_balance, execute_whitehat_rescue
from web3 import Web3

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("AegisScanner")

def run_multichain_scanner():
    logger.info("[SCANNER] Starting AegisForge multichain block scanner...")
    connections = {}
    for chain, rpc in RPC_ENDPOINTS.items():
        try:
            w3 = Web3(Web3.HTTPProvider(rpc))
            if w3.is_connected():
                connections[chain] = w3
                logger.info(f"[SCANNER] Connected to {chain} successfully.")
            else:
                logger.warning(f"[SCANNER] Failed to connect to {chain}.")
        except Exception as e:
            logger.error(f"[SCANNER] Error connecting to {chain}: {e}")

    while True:
        for chain, w3 in connections.items():
            try:
                latest_block = w3.eth.block_number
                block = w3.eth.get_block(latest_block, full_transactions=True)
                for tx in block.get("transactions", []):
                    if tx.get("to") is None:
                        tx_receipt = w3.eth.get_transaction_receipt(tx["hash"])
                        contract_address = tx_receipt.get("contractAddress")
                        if contract_address:
                            logger.info(f"[{chain}] NEW CONTRACT DEPLOYED: {contract_address}")
                            balance = check_contract_balance(contract_address, chain)
                            if balance > 0.01:
                                logger.warning(f"[{chain}] ALERT! Target contract {contract_address} has {balance} ETH!")
                                execute_whitehat_rescue(contract_address, chain)
            except Exception as e:
                logger.error(f"[{chain} SCANNER ERROR]: {e}")
        time.sleep(5)

if __name__ == "__main__":
    run_multichain_scanner()
