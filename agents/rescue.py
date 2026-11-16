import requests
import logging
from agents.config import RPC_ENDPOINTS, DEFAULT_CHAIN

logger = logging.getLogger("RescueModule")

def check_contract_balance(contract_address, chain=DEFAULT_CHAIN):
    try:
        rpc_url = RPC_ENDPOINTS.get(chain)
        if not rpc_url:
            logger.error(f"Unknown chain: {chain}")
            return "0.0 (Unknown chain)"
        
        payload = {
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": [contract_address, "latest"],
            "id": 1
        }
        
        logger.info(f"Sending RPC request to {rpc_url} for address {contract_address}")
        resp = requests.post(rpc_url, json=payload, timeout=3)
        logger.info(f"RPC response status: {resp.status_code}")
        
        data = resp.json()
        if "result" in data:
            balance_wei = int(data["result"], 16)
            balance_eth = balance_wei / 10**18
            return str(balance_eth)
        elif "error" in data:
            err_msg = data["error"].get("message", "Unknown")
            logger.error(f"RPC Error JSON: {err_msg}")
            return f"RPC Error: {err_msg}"
        return "0.0 (Invalid response)"
    except requests.exceptions.Timeout:
        logger.error("RPC request timed out after 3 seconds")
        return "0.0 (Timeout)"
    except Exception as e:
        logger.error(f"Exception in check_contract_balance: {str(e)}")
        return f"Error: {str(e)}"
