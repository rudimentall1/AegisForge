import subprocess
import os
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] [SANDBOX] %(message)s')

SANDBOX_DIR = "/opt/agent-farm/agents/sandbox"

def run_anvil_fork_test(rpc_url: str, test_file_path: str) -> bool:
    logging.info(f"Running sandbox verification for {test_file_path} against fork URL...")
    
    if not os.path.exists(test_file_path):
        logging.error(f"Test file not found: {test_file_path}")
        return False
        
    try:
        cmd = [
            "forge", "test",
            "--match-path", test_file_path,
            "--fork-url", rpc_url,
            "--vvv"
        ]
        
        result = subprocess.run(cmd, cwd=SANDBOX_DIR, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            logging.info("Sandbox verification SUCCESS: Exploit/Test passed successfully!")
            return True
        else:
            logging.warning(f"Sandbox verification FAILED or test reverted:\n{result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        logging.error("Sandbox verification timed out!")
        return False
    except Exception as e:
        logging.error(f"Error running sandbox test: {e}")
        return False

if __name__ == "__main__":
    print("Sandbox runner module loaded successfully.")
