import sqlite3
import os

DB_PATH = "/opt/agent-farm/data/agent_farm_backup_before_test.db"

def show_metrics():
	conn = sqlite3.connect(DB_PATH)
	cursor = conn.cursor()
	print("=" * 60)
	print("       AEGISFORGE SECURITY FACTORY — METRICS DASHBOARD")
	print("=" * 60)
	try:
		statuses = cursor.execute("SELECT status, COUNT(*) FROM queue GROUP BY status").fetchall()
		print("\n[📊 Task Queue Statuses]")
		for s, c in statuses:
			print(f"  - {s.upper()}: {c}")
	except Exception as e:
		print(f"[!] Error: {e}")
	patches = os.listdir("patches") if os.path.exists("patches") else []
	print(f"\n[🛡️ Remediation Status]")
	print(f"  - Total Generated Patches: {len(patches)}")
	for p in patches:
		print(f"    -> {p}")
	print("=" * 60)
	conn.close()

if __name__ == "__main__":
	show_metrics()
