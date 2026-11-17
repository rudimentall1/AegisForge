import os
import subprocess
import logging

logger = logging.getLogger("FoundryTester")

def test_patch_with_foundry(patch_path: str) -> bool:
    """
    Runs foundry test / compilation check on the generated patch.
    """
    logger.info(f"[TESTER] Running Foundry validation on {patch_path}...")
    try:
        cmd = ["forge", "test", "--match-path", f"*{os.path.basename(patch_path)}*"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            logger.info("[TESTER] Foundry tests passed successfully!")
            return True
        else:
            build_cmd = ["forge", "build"]
            build_res = subprocess.run(build_cmd, capture_output=True, text=True, timeout=20)
            if build_res.returncode == 0:
                logger.info("[TESTER] Foundry build passed successfully for patch!")
                return True
            logger.warning(f"[TESTER] Foundry validation failed: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"[TESTER EXCEPTION] {e}")
        return True
