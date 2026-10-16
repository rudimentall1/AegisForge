#!/usr/bin/env python3
"""Safely mark duplicate research-case root tasks without deleting audit history.

Default mode is dry-run. Use --apply only after reviewing the JSON summary.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sqlite3
import sys


DEFAULT_DB = Path(
    os.environ.get(
        "AEGISFORGE_DB_PATH",
        str(Path(__file__).resolve().parents[1] / "data" / "agent_farm.db"),
    )
)


def migrate(db_path: Path, apply: bool) -> dict:
    if not db_path.exists():
        raise FileNotFoundError(f"database does not exist: {db_path}")

    connection = sqlite3.connect(db_path, timeout=30)
    connection.row_factory = sqlite3.Row
    summary = {"dry_run": not apply, "cases": 0, "kept": [], "deduped": []}
    try:
        if apply:
            connection.execute("BEGIN IMMEDIATE")

        duplicate_cases = connection.execute(
            """
            SELECT research_case_id, COUNT(*) AS root_count
            FROM queue
            WHERE parent_task_id IS NULL AND research_case_id IS NOT NULL
            GROUP BY research_case_id
            HAVING COUNT(*) > 1
            ORDER BY research_case_id
            """
        ).fetchall()

        summary["cases"] = len(duplicate_cases)
        for case_row in duplicate_cases:
            case_id = case_row["research_case_id"]
            roots = connection.execute(
                """
                SELECT id, created_at, planner_decision
                FROM queue
                WHERE parent_task_id IS NULL AND research_case_id = ?
                ORDER BY created_at ASC, id ASC
                """,
                (case_id,),
            ).fetchall()
            if len(roots) <= 1:
                continue

            first = roots[0]
            summary["kept"].append({
                "root_id": first["id"],
                "case_id": case_id,
                "reason": "first_root",
            })
            print(
                f"KEEP root={first['id']} case={case_id} reason=first_root",
                file=sys.stderr,
            )

            for root in roots[1:]:
                root_id = root["id"]
                if root["planner_decision"] == "DEDUPED_ROOT":
                    continue

                child_row = connection.execute(
                    """
                    SELECT COUNT(*) FROM queue
                    WHERE parent_task_id = ? AND status = 'completed'
                    """,
                    (root_id,),
                ).fetchone()
                completed_children = int(child_row[0] or 0)

                if completed_children > 0:
                    summary["kept"].append({
                        "root_id": root_id,
                        "case_id": case_id,
                        "reason": "has_completed_children",
                        "count": completed_children,
                    })
                    print(
                        f"KEEP root={root_id} case={case_id} "
                        f"reason=has_completed_children count={completed_children}",
                        file=sys.stderr,
                    )
                    continue

                summary["deduped"].append({"root_id": root_id, "case_id": case_id})
                print(f"DEDUP {root_id} case={case_id}", file=sys.stderr)
                if apply:
                    connection.execute(
                        """
                        UPDATE queue SET planner_decision = 'DEDUPED_ROOT'
                        WHERE id = ?
                          AND (planner_decision IS NULL OR planner_decision != 'DEDUPED_ROOT')
                        """,
                        (root_id,),
                    )

        if apply:
            connection.commit()
        else:
            connection.rollback()
        return summary
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="show changes without modifying the database (default)")
    mode.add_argument("--apply", action="store_true", help="apply DEDUPED_ROOT markers transactionally")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="SQLite database path")
    args = parser.parse_args(argv)

    try:
        summary = migrate(args.db, apply=args.apply)
    except (OSError, sqlite3.Error) as exc:
        print(f"migration failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
