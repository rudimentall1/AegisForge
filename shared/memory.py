import json
import sqlite3
from pathlib import Path


DB_PATH = Path("/opt/agent-farm/data/agent_farm.db")

# Memory is a bounded convenience cache. Durable research evidence belongs in
# the queue/evidence ledger, not in an ever-growing task-result history.
MAX_RESULT_BYTES = 8192
MAX_RETAINED_TASKS = 500


class Memory:
    def __init__(self):
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)

        self.db = sqlite3.connect(
            DB_PATH,
            timeout=30,
            check_same_thread=False,
        )
        self.db.execute("PRAGMA busy_timeout=30000")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA wal_autocheckpoint=1000")
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

    @staticmethod
    def _bounded_text(text):
        suffix = "\n...[truncated]"
        raw = str(text).encode("utf-8")
        if len(raw) <= MAX_RESULT_BYTES:
            return str(text)
        keep = max(0, MAX_RESULT_BYTES - len(suffix.encode("utf-8")))
        return raw[:keep].decode("utf-8", "ignore") + suffix

    @classmethod
    def _bounded_result(cls, result):
        text = json.dumps(
            result,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )
        return cls._bounded_text(text)

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
                self._bounded_result(task.result),
                task.created_at,
            ),
        )
        self.db.commit()
        self.compact()

    def compact(self, limit=MAX_RETAINED_TASKS):
        """Keep only a bounded recent task-memory cache.

        Queue history and the evidence ledger remain the durable sources.
        This cache is intentionally disposable and must never grow with
        agent activity.
        """
        limit = int(limit)
        if limit <= 0:
            raise ValueError("limit must be positive")

        rows = self.db.execute(
            "SELECT task_id, result FROM tasks"
        ).fetchall()
        for task_id, result in rows:
            if result is not None:
                bounded = self._bounded_text(result)
                if bounded != result:
                    self.db.execute(
                        "UPDATE tasks SET result = ? WHERE task_id = ?",
                        (bounded, task_id),
                    )

        self.db.execute(
            """
            DELETE FROM tasks
            WHERE task_id IN (
                SELECT task_id
                FROM tasks
                ORDER BY created_at DESC, task_id DESC
                LIMIT -1 OFFSET ?
            )
            """,
            (limit,),
        )
        deleted = self.db.execute("SELECT changes()").fetchone()[0]
        self.db.commit()
        return max(0, int(deleted or 0))

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

    def close(self):
        self.db.close()
