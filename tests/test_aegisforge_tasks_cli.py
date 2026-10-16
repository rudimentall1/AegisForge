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



def test_case_reviews_lists_open_reviews(tmp_path):
    from shared.queue import TaskQueue

    db = tmp_path / "queue.db"
    queue = TaskQueue(db_path=db)
    review_id = queue.create_human_review("cli-case-review", "all branches terminal")
    queue.db.close()

    result = run_cli(db, "case", "reviews")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["count"] == 1
    assert payload["reviews"][0]["id"] == review_id
    assert payload["reviews"][0]["status"] == "OPEN"


def test_case_resolve_marks_review_resolved(tmp_path):
    from shared.queue import TaskQueue

    db = tmp_path / "queue.db"
    queue = TaskQueue(db_path=db)
    review_id = queue.create_human_review("cli-case-resolve", "all branches terminal")
    queue.db.close()

    result = run_cli(db, "case", "resolve", review_id, "new round needed")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload == {
        "review_id": review_id,
        "resolved": True,
        "resolution": "new round needed",
    }

    queue = TaskQueue(db_path=db)
    reviews = queue.list_human_reviews(status="RESOLVED")
    queue.db.close()
    assert len(reviews) == 1
    assert reviews[0]["id"] == review_id
    assert reviews[0]["resolution"] == "new round needed"


def test_case_resolve_returns_error_for_unknown_id(tmp_path):
    result = run_cli(
        tmp_path / "queue.db",
        "case",
        "resolve",
        "missing-review-id",
        "new round needed",
    )
    assert result.returncode == 1
    assert json.loads(result.stdout)["resolved"] is False



def test_case_rounds_public_lists_only_disclosure_metadata(tmp_path):
    from shared.queue import TaskQueue

    db = tmp_path / "queue.db"
    case_file = tmp_path / "case.json"
    case = {
        "case_id": "cli-round-case",
        "target_repository": "example/project",
        "target_commit": "a" * 40,
        "scope_url": "https://example.com/scope",
        "scope_digest": "b" * 64,
        "scope_reviewed_on": "2026-10-16",
        "hypothesis": "private hypothesis text must not be returned",
        "attacker_capability": "unprivileged caller",
        "expected_invariant": "accounting invariant",
        "falsification_criteria": "counter-test preserves invariant",
        "execution_mode": "local",
        "status": "ready",
        "allowed_techniques": ["source_pattern"],
        "rounds": [{
            "round_id": "cli-round-001",
            "technique": "source_pattern",
            "hypothesis": "private round hypothesis",
            "expected_evidence_atoms": ["source line", "counter-test"],
            "falsification_criteria": "counter-test disproves claim",
            "priority": 3,
            "disclosure_deadline_days": 90,
        }],
    }
    case_file.write_text(json.dumps(case), encoding="utf-8")
    registered = run_cli(db, "case", "register", str(case_file))
    assert registered.returncode == 0, registered.stderr

    queue = TaskQueue(db_path=db)
    queue.create_round_transparency(
        round_id="cli-round-001",
        case_id=case["case_id"],
        technique="source_pattern",
        started_at="2026-10-16T00:00:00+00:00",
        disclosure_deadline="2027-01-14T00:00:00+00:00",
    )
    queue.db.close()

    result = run_cli(db, "case", "rounds", "--public", case["case_id"])
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["count"] == 1
    assert payload["rounds"][0] == {
        "round_id": "cli-round-001",
        "technique": "source_pattern",
        "started_at": "2026-10-16T00:00:00+00:00",
        "deadline": "2027-01-14T00:00:00+00:00",
        "status": "OPEN",
        "verdict": None,
    }
    assert "private round hypothesis" not in result.stdout
