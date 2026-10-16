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


def test_case_register_and_forensic_task_submission(tmp_path):
    db = tmp_path / "queue.db"
    case_file = tmp_path / "case.json"
    case = {
        "case_id": "cli-case-001",
        "target_repository": "example/project",
        "target_commit": "a" * 40,
        "scope_url": "https://example.com/scope",
        "scope_digest": "b" * 64,
        "scope_reviewed_on": "2026-10-16",
        "hypothesis": "A bounded local test may violate an accounting invariant.",
        "attacker_capability": "An unprivileged caller can invoke the public method.",
        "expected_invariant": "The recorded balance equals the independently calculated balance.",
        "falsification_criteria": "Counter-tests preserve the invariant for all tested transitions.",
        "execution_mode": "local",
        "status": "ready",
    }
    case_file.write_text(json.dumps(case), encoding="utf-8")

    registered = run_cli(db, "case", "register", str(case_file))
    assert registered.returncode == 0, registered.stderr
    assert json.loads(registered.stdout)["case_id"] == case["case_id"]

    submitted = run_cli(
        db, "submit", "--role", "crypto_analyst", "--case-id", case["case_id"],
        "Run local invariant test",
    )
    assert submitted.returncode == 0, submitted.stderr
    task = json.loads(submitted.stdout)
    assert task["status"] == "pending"
    assert task["role"] == "crypto_analyst"

    status = run_cli(db, "case", "show", case["case_id"])
    assert status.returncode == 0, status.stderr
    assert json.loads(status.stdout)["target_commit"] == case["target_commit"]


def test_forensic_cli_submission_without_case_is_rejected(tmp_path):
    result = run_cli(
        tmp_path / "queue.db",
        "submit",
        "--role",
        "crypto_analyst",
        "unbound research task",
    )
    assert result.returncode != 0
    assert "requires --case-id" in result.stderr
