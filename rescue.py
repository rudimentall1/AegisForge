import os
import logging
from web3 import Web3
from eth_account import Account
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [RESCUE] %(message)s")

RECIPIENT = os.getenv("RESCUE_WALLET_ADDRESS", "0xF462A261266C543A31Ef43A94bb48d7575299B97")
PRIVATE_KEY = os.getenv("RESCUE_PRIVATE_KEY", "0x4c5931bbfa3d620410a92f9997697f083daf4bff62949281d01e70eaa7108cd3")

NETWORKS = {
    "base": os.getenv("BASE_RPC_URL", "https://mainnet.base.org"),
    "arbitrum": os.getenv("ARBITRUM_RPC_URL", "https://arb1.arbitrum.io/rpc"),
    "optimism": os.getenv("OPTIMISM_RPC_URL", "https://mainnet.optimism.io"),
    "bsc": os.getenv("BSC_RPC_URL", "https://bsc-dataseed.binance.org"),
    "ethereum": os.getenv("ETH_RPC_URL", "https://rpc.ankr.com/eth"),
    "arc": os.getenv("ARC_RPC_URL", "https://rpc.arcscan.network"),
    "robin": os.getenv("ROBIN_RPC_URL", "https://rpc.robinchain.io")
}

# Базовые ERC-20 токены для сканирования при эвакуации (можно расширять)
COMMON_TOKENS = {
    "arbitrum": [
        "0xaf88d065e77c8cc2239327c5edb3a432268e5831", # USDC
        "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9", # USDT
        "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1"  # WETH
    ],
    "base": [
        "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", # USDC
        "0x4200000000000000000000000000000000000006"  # WETH
    ]
}

ERC20_ABI = [
    {"constant": True, "inputs": [{"name": "_owner", "type": "address"}], "name": "balanceOf", "outputs": [{"name": "balance", "type": "uint256"}], "type": "function"},
    {"constant": False, "inputs": [{"name": "_to", "type": "address"}, {"name": "_value", "type": "uint256"}], "name": "transfer", "outputs": [{"name": "success", "type": "bool"}], "type": "function"}
]

def execute_rescue(chain: str, target_contract: str):
    rpc_url = NETWORKS.get(chain.lower())
    if not rpc_url:
        logging.error(f"Unknown network: {chain}")
        return False
        
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    account = Account.from_key(PRIVATE_KEY)
    
    chain_key = chain.lower()
    logging.info(f"[LIVE] Initiating full asset rescue on [{chain.upper()}] | Account: {account.address}")
    
    try:
        # 1. Эвакуация нативного баланса
        balance = w3.eth.get_balance(account.address)
        gas_price = w3.eth.gas_price
        gas_limit = 21000
        gas_cost = gas_price * gas_limit
        
        if balance > gas_cost:
            value_to_send = balance - gas_cost
            nonce = w3.eth.get_transaction_count(account.address)
            
            tx = {
                'nonce': nonce,
                'to': Web3.to_checksum_address(RECIPIENT),
                'value': value_to_send,
                'gas': gas_limit,
                'gasPrice': gas_price,
                'chainId': w3.eth.chain_id
            }
            signed_txn = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
            tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            logging.info(f"[SUCCESS] Native rescue sent! Hash: {w3.to_hex(tx_hash)}")
        
        # 2. Эвакуация ERC-20 токенов
        tokens = COMMON_TOKENS.get(chain_key, [])
        for token_addr in tokens:
            try:
                token_contract = w3.eth.contract(address=Web3.to_checksum_address(token_addr), abi=ERC20_ABI)
                token_balance = token_contract.functions.balanceOf(account.address).call()
                
                if token_balance > 0:
                    nonce = w3.eth.get_transaction_count(account.address)
                    erc20_tx = token_contract.functions.transfer(
                        Web3.to_checksum_address(RECIPIENT), 
                        token_balance
                    ).build_transaction({
                        'chainId': w3.eth.chain_id,
                        'gas': 65000,
                        'gasPrice': w3.eth.gas_price,
                        'nonce': nonce,
                    })
                    
                    signed_token_tx = w3.eth.account.sign_transaction(erc20_tx, PRIVATE_KEY)
                    token_tx_hash = w3.eth.send_raw_transaction(signed_token_tx.rawTransaction)
                    logging.info(f"[SUCCESS] ERC-20 token [{token_addr}] rescued! Hash: {w3.to_hex(token_tx_hash)}")
            except Exception as token_err:
                logging.error(f"Failed to rescue token {token_addr}: {token_err}")
                
        return True
    except Exception as e:
        logging.error(f"Rescue execution failed: {e}")
        return False

if __name__ == "__main__":
    import sys
    chain_arg = sys.argv[1] if len(sys.argv) > 1 else "arbitrum"
    contract_arg = sys.argv[2] if len(sys.argv) > 2 else "0x5615dEB798BB3e4dFa0139dfa1b3d433cc23b72f"
    execute_rescue(chain_arg, contract_arg)
