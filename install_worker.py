import os

code = '''import os
import time
import json
import logging
from shared.task_queue import TaskQueue
from validator import validate_slither_report
from remediation import generate_security_patch

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def run_worker():
queue = TaskQueue()
logging.info("[WORKER] AegisForge security worker started...")
while True:
    try:
        cursor = queue.db.cursor()
        cursor.execute("BEGIN IMMEDIATE")
        row = cursor.execute("SELECT id, description, research_case_id FROM queue WHERE status = 'pending' ORDER BY created_at LIMIT 1").fetchone()
        if not row:
            cursor.close()
            queue.db.commit()
            time.sleep(2)
            continue
        
        task_id, description, case_id = row[0], row[1], row[2]
        cursor.execute("UPDATE queue SET status = 'running' WHERE id = ?", (task_id,))
        queue.db.commit()
        cursor.close()
        
        chain_id = "optimism"
        contract_address = "0x965c847C0d0EF4Fae81e46Fc552F8D69F53819D6"
        logging.info(f"[WORKER] Processing task {task_id}...")
        
        mock_slither_output = f"High severity reentrancy detected in contract {contract_address} at withdraw() function."
        mock_source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vulnerable {
mapping(address => uint) public balances;
function withdraw() public {
    (bool sent, ) = msg.sender.call{value: balances[msg.sender]}("");
    require(sent);
    balances[msg.sender] = 0;
}
}
"""
        validation = validate_slither_report(contract_address, chain_id, mock_slither_output)
        if validation.get("is_critical"):
            logging.warning(f"[ALERT] Critical vulnerability confirmed on {contract_address}!")
            patch = generate_security_patch(mock_source, json.dumps(validation))
            patch_dir = "/opt/agent-farm/patches"
            os.makedirs(patch_dir, exist_ok=True)
            patch_path = os.path.join(patch_dir, f"{chain_id}_{contract_address}.sol")
            with open(patch_path, "w", encoding="utf-8") as f:
                f.write(patch)
            logging.info(f"[REMEDIATION] Secure patch saved to {patch_path}")
        else:
            logging.info("[WORKER] Contract passed security checks.")
        
        cursor = queue.db.cursor()
        cursor.execute("UPDATE queue SET status = 'completed', finished_at = CURRENT_TIMESTAMP WHERE id = ?", (task_id,))
        queue.db.commit()
        cursor.close()
        
    except Exception as e:
        logging.error(f"[WORKER ERROR] {e}")
        time.sleep(2)

if __name__ == "__main__":
run_worker()
'''

with open("agents/worker.py", "w", encoding="utf-8") as f:
f.write(code)
print("[OK] agents/worker.py installed successfully without shell corruption!")
