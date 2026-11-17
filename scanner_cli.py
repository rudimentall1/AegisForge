import sys
from agents.worker import run_slither_audit, send_telegram_alert

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scanner_cli.py <path_to_sol_file_or_dir> [target_address]")
        sys.exit(1)
    
    target = sys.argv[1]
    addr = sys.argv[2] if len(sys.argv) > 2 else "ManualTarget"
    print(f"[*] Starting real Slither security audit for: {target}")
    res = run_slither_audit(target, addr)
    print(f"[*] Audit complete: {res}")
