import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_cli(db, *args):
    return subprocess.run(
        [sys.executable, str(ROOT / "aegisforge.py"), "tasks", *args, "--db", str(db)],
        cwd=ROOT, capture_output=True, text=True, timeout=10,
    )


def test_submit_and_status_on_isolated_database(tmp_path):
    db = tmp_path / "queue.db"
    submitted = run_cli(db, "submit", "--role", "researcher", "Find public sources about PQC migration")
    assert submitted.returncode == 0, submitted.stderr
    payload = json.loads(submitted.stdout)
    assert payload["status"] == "pending"
    assert payload["role"] == "researcher"

    status = run_cli(db, "status", payload["task_id"])
    assert status.returncode == 0, status.stderr
    task = json.loads(status.stdout)
    assert task["task_id"] == payload["task_id"]
    assert task["status"] == "pending"
    assert task["description"] == "Find public sources about PQC migration"


def test_submit_rejects_unknown_role(tmp_path):
    result = run_cli(tmp_path / "queue.db", "submit", "--role", "root", "do things")
    assert result.returncode != 0
    assert "invalid choice" in result.stderr
