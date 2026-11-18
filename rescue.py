import os
import json
from web3 import Web3
from eth_account import Account

class WhiteHatRescuer:
    def __init__(self, rpc_url: str, private_key: str, safe_multisig: str):
        self.rpc_url = rpc_url
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.account = Account.from_key(private_key)
        self.safe_multisig = safe_multisig

    def simulate_and_rescue(self, target_contract: str, exploit_payload: dict) -> dict:
        print(f"[*] Инициализация песочницы Anvil для контракта: {target_contract}")
        fork_w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
        
        if not fork_w3.is_connected():
            return {
                "success": False,
                "error": "Anvil sandbox node is not running on port 8545"
            }

        try:
            nonce = fork_w3.eth.get_transaction_count(self.account.address)
            tx = {
                'to': Web3.to_checksum_address(target_contract),
                'value': 0,
                'gas': 500000,
                'gasPrice': fork_w3.eth.gas_price,
                'nonce': nonce,
                'chainId': fork_w3.eth.chain_id,
                'data': exploit_payload.get("calldata", "0x")
            }

            signed_tx = fork_w3.eth.account.sign_transaction(tx, self.account.key)
            tx_hash = fork_w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            receipt = fork_w3.eth.wait_for_transaction_receipt(tx_hash)

            if receipt['status'] == 1:
                print(f"[+] Песочница: Эвакуация успешна! TxHash: {receipt['transactionHash'].hex()}")
                return {
                    "success": True,
                    "tx_hash": receipt['transactionHash'].hex(),
                    "gas_used": receipt['gasUsed'],
                    "rescued_to": self.safe_multisig
                }
            else:
                return {
                    "success": False,
                    "error": "Transaction reverted in sandbox EVM"
                }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
