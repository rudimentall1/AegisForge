#!/usr/bin/env python3
"""Safely migrate round_transparency to a (case_id, round_id) primary key.

Dry-run is the default. Pass --apply only after reviewing the reported plan.
"""
import argparse
import json
import os
import sqlite3
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB_PATH = Path(
    os.environ.get("AEGISFORGE_DB_PATH", str(REPO_ROOT / "agent_farm.db"))
)

CREATE_TABLE_SQL = """
CREATE TABLE {table_name} (
    case_id TEXT NOT NULL,
    round_id TEXT NOT NULL,
    technique TEXT NOT NULL,
    started_at TEXT NOT NULL,
    disclosure_deadline TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',
    completed_at TEXT,
    verdict TEXT,
    extension_granted_at TEXT,
    extension_reason TEXT,
    PRIMARY KEY (case_id, round_id)
)
"""

INDEX_SQL = (
    "CREATE INDEX IF NOT EXISTS idx_rt_status_deadline "
    "ON round_transparency(status, disclosure_deadline)",
    "CREATE INDEX IF NOT EXISTS idx_round_transparency_case_status "
    "ON round_transparency(case_id, status)",
)


def primary_key_columns(connection):
    rows = connection.execute("PRAGMA table_info(round_transparency)").fetchall()
    return [
        row[1]
        for row in sorted((row for row in rows if row[5]), key=lambda row: row[5])
    ]


def migrate(db_path, apply=False):
    path = Path(db_path)
    if not path.exists():
        return {
            "database": str(path), "table_exists": False, "needs_migration": False,
            "applied": False, "message": "Database file does not exist; nothing changed.",
        }

    connection = sqlite3.connect(path, timeout=30)
    try:
        exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'round_transparency'"
        ).fetchone()
        if not exists:
            return {
                "database": str(path), "table_exists": False, "needs_migration": False,
                "applied": False, "message": "round_transparency does not exist; nothing changed.",
            }

        old_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(round_transparency)")
        }
        required = {
            "case_id", "round_id", "technique", "started_at",
            "disclosure_deadline", "status", "completed_at", "verdict",
        }
        missing = sorted(required - old_columns)
        if missing:
            raise RuntimeError(f"round_transparency missing required columns: {missing}")

        row_count = connection.execute(
            "SELECT COUNT(*) FROM round_transparency"
        ).fetchone()[0]
        pk = primary_key_columns(connection)
        if pk == ["case_id", "round_id"]:
            return {
                "database": str(path), "table_exists": True, "primary_key": pk,
                "row_count": row_count, "needs_migration": False, "applied": False,
                "message": "Already migrated; no changes made.",
            }

        report = {
            "database": str(path), "table_exists": True, "primary_key_before": pk,
            "primary_key_after": ["case_id", "round_id"],
            "row_count_before": row_count, "needs_migration": True,
            "applied": False, "mode": "apply" if apply else "dry-run",
        }
        if not apply:
            report["message"] = "Dry-run only. Re-run with --apply to perform the migration."
            return report

        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DROP TABLE IF EXISTS round_transparency_new")
        connection.execute(CREATE_TABLE_SQL.format(table_name="round_transparency_new"))

        target_columns = (
            "case_id", "round_id", "technique", "started_at", "disclosure_deadline",
            "status", "completed_at", "verdict", "extension_granted_at", "extension_reason",
        )
        select_expressions = [
            column if column in old_columns else "NULL AS " + column
            for column in target_columns
        ]
        connection.execute(
            "INSERT INTO round_transparency_new (" + ", ".join(target_columns) + ") "
            "SELECT " + ", ".join(select_expressions) + " FROM round_transparency"
        )
        migrated_count = connection.execute(
            "SELECT COUNT(*) FROM round_transparency_new"
        ).fetchone()[0]
        if migrated_count != row_count:
            raise RuntimeError(
                f"row count mismatch: before={row_count}, after={migrated_count}"
            )

        connection.execute("DROP TABLE round_transparency")
        connection.execute("ALTER TABLE round_transparency_new RENAME TO round_transparency")
        for statement in INDEX_SQL:
            connection.execute(statement)
        connection.commit()

        report.update({
            "row_count_after": migrated_count, "applied": True,
            "message": "Migration committed successfully.",
        })
        return report
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db-path", type=Path, default=DEFAULT_DB_PATH)
    parser.add_argument(
        "--apply", action="store_true",
        help="Apply the migration. Without this flag, the script is dry-run only.",
    )
    args = parser.parse_args()
    print(json.dumps(migrate(args.db_path, apply=args.apply), indent=2))


if __name__ == "__main__":
    main()
