import importlib.util
import sqlite3
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "migrate_cases_to_rounds.py"
SPEC = importlib.util.spec_from_file_location("migrate_cases_to_rounds", SCRIPT)
MIGRATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MIGRATION)


def make_db(path, roots):
    connection = sqlite3.connect(path)
    connection.execute(
        """
        CREATE TABLE queue (
            id TEXT PRIMARY KEY,
            parent_task_id TEXT,
            research_case_id TEXT,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL,
            planner_decision TEXT
        )
        """
    )
    for row in roots:
        connection.execute(
            """
            INSERT INTO queue (id, parent_task_id, research_case_id, created_at, status, planner_decision)
            VALUES (?, NULL, ?, ?, ?, ?)
            """,
            (
                row["id"], row["case"], row["created"], row.get("status", "completed"),
                row.get("decision"),
            ),
        )
        for child in row.get("children", []):
            connection.execute(
                """
                INSERT INTO queue (id, parent_task_id, research_case_id, created_at, status, planner_decision)
                VALUES (?, ?, ?, ?, ?, NULL)
                """,
                (child["id"], row["id"], row["case"], child["created"], child["status"],),
            )
    connection.commit()
    connection.close()


def read_decisions(path):
    with sqlite3.connect(path) as connection:
        return dict(connection.execute("SELECT id, planner_decision FROM queue WHERE parent_task_id IS NULL"))


def test_dry_run_does_not_modify_db(tmp_path):
    db = tmp_path / "queue.db"
    make_db(db, [
        {"id": "root-a", "case": "case-a", "created": "2026-01-01T00:00:00Z"},
        {"id": "root-b", "case": "case-a", "created": "2026-01-02T00:00:00Z"},
    ])

    summary = MIGRATION.migrate(db, apply=False)

    assert summary["dry_run"] is True
    assert summary["cases"] == 1
    assert [row["root_id"] for row in summary["deduped"]] == ["root-b"]
    assert read_decisions(db) == {"root-a": None, "root-b": None}


def test_apply_keeps_root_with_completed_children(tmp_path):
    db = tmp_path / "queue.db"
    make_db(db, [
        {"id": "root-a", "case": "case-a", "created": "2026-01-01T00:00:00Z"},
        {
            "id": "root-b", "case": "case-a", "created": "2026-01-02T00:00:00Z",
            "children": [{"id": "child-b", "created": "2026-01-03T00:00:00Z", "status": "completed"}],
        },
    ])

    summary = MIGRATION.migrate(db, apply=True)

    assert [row["root_id"] for row in summary["kept"]] == ["root-a", "root-b"]
    assert summary["deduped"] == []
    assert read_decisions(db) == {"root-a": None, "root-b": None}


def test_apply_dedupes_empty_duplicate_root(tmp_path):
    db = tmp_path / "queue.db"
    make_db(db, [
        {"id": "root-a", "case": "case-a", "created": "2026-01-01T00:00:00Z"},
        {"id": "root-b", "case": "case-a", "created": "2026-01-02T00:00:00Z", "status": "failed"},
    ])

    summary = MIGRATION.migrate(db, apply=True)

    assert [row["root_id"] for row in summary["deduped"]] == ["root-b"]
    assert read_decisions(db) == {"root-a": None, "root-b": "DEDUPED_ROOT"}
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT status FROM queue WHERE id = 'root-b'").fetchone()[0] == "failed"


def test_idempotent_on_second_run(tmp_path):
    db = tmp_path / "queue.db"
    make_db(db, [
        {"id": "root-a", "case": "case-a", "created": "2026-01-01T00:00:00Z"},
        {"id": "root-b", "case": "case-a", "created": "2026-01-02T00:00:00Z"},
    ])

    first = MIGRATION.migrate(db, apply=True)
    second = MIGRATION.migrate(db, apply=True)

    assert len(first["deduped"]) == 1
    assert second["deduped"] == []
    assert read_decisions(db) == {"root-a": None, "root-b": "DEDUPED_ROOT"}


def test_single_root_case_untouched(tmp_path):
    db = tmp_path / "queue.db"
    make_db(db, [
        {"id": "root-a", "case": "case-a", "created": "2026-01-01T00:00:00Z"},
    ])

    summary = MIGRATION.migrate(db, apply=True)

    assert summary["cases"] == 0
    assert summary["kept"] == []
    assert summary["deduped"] == []
    assert read_decisions(db) == {"root-a": None}
