import sqlite3

from scripts import migrate_round_transparency_composite_key as migration
from shared import queue
from scripts.migrate_round_transparency_composite_key import migrate, primary_key_columns


def _legacy_db(path):
    connection = sqlite3.connect(path)
    connection.execute("""
        CREATE TABLE round_transparency (
            round_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            technique TEXT NOT NULL,
            started_at TEXT NOT NULL,
            disclosure_deadline TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'OPEN',
            completed_at TEXT,
            verdict TEXT
        )
    """)
    connection.execute(
        "INSERT INTO round_transparency "
        "(round_id, case_id, technique, started_at, disclosure_deadline, status) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            "r1-source-pattern", "profanity-round-test-1", "source_pattern",
            "2026-10-16T13:49:00+00:00", "2026-11-15T13:49:00+00:00", "COMPLETED",
        ),
    )
    connection.commit()
    connection.close()


def test_migration_dry_run_does_not_modify_database(tmp_path):
    path = tmp_path / "legacy.sqlite"
    _legacy_db(path)
    result = migrate(path)
    connection = sqlite3.connect(path)
    assert result["needs_migration"] is True
    assert result["applied"] is False
    assert primary_key_columns(connection) == ["round_id"]
    assert connection.execute("SELECT COUNT(*) FROM round_transparency").fetchone()[0] == 1
    connection.close()


def test_migration_apply_preserves_rows_and_is_idempotent(tmp_path):
    path = tmp_path / "legacy.sqlite"
    _legacy_db(path)
    result = migrate(path, apply=True)
    connection = sqlite3.connect(path)
    assert result["applied"] is True
    assert result["row_count_before"] == result["row_count_after"] == 1
    assert primary_key_columns(connection) == ["case_id", "round_id"]
    assert connection.execute(
        "SELECT case_id, round_id, status FROM round_transparency"
    ).fetchone() == ("profanity-round-test-1", "r1-source-pattern", "COMPLETED")
    connection.close()

    second = migrate(path, apply=True)
    assert second["needs_migration"] is False
    assert second["applied"] is False


def test_default_path_matches_queue_default():
    assert migration.db_path == queue.DB_PATH
    assert migration.DEFAULT_DB_PATH == queue.DB_PATH
