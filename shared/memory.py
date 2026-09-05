import json
import sqlite3
from pathlib import Path


DB_PATH = Path("/opt/agent-farm/data/agent_farm.db")


class Memory:
    def __init__(self):
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)

        self.db = sqlite3.connect(DB_PATH)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY,
                description TEXT NOT NULL,
                status TEXT NOT NULL,
                result TEXT,
                created_at TEXT NOT NULL
            )
        """)
        self.db.commit()

    def save_task(self, task):
        self.db.execute(
            """
            INSERT OR REPLACE INTO tasks
            (task_id, description, status, result, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                task.task_id,
                task.description,
                task.status,
                json.dumps(
                    task.result,
                    ensure_ascii=False
                ),
                task.created_at,
            ),
        )
        self.db.commit()

    def recent(self, limit=10):
        rows = self.db.execute(
            """
            SELECT task_id, description, status, result, created_at
            FROM tasks
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        return rows
