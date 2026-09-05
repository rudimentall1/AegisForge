import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path


DB_PATH = Path("/opt/agent-farm/data/agent_farm.db")


class TaskQueue:
    def __init__(self):
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)

        self.db = sqlite3.connect(
            DB_PATH,
            timeout=30,
            check_same_thread=False,
        )

        self.db.execute("""
            CREATE TABLE IF NOT EXISTS queue (
                id TEXT PRIMARY KEY,
                description TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                worker TEXT,
                created_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                role TEXT,
                parent_task_id TEXT,
                result TEXT
            )
        """)

        columns = {
            row[1]
            for row in self.db.execute("PRAGMA table_info(queue)")
        }

        if "result" not in columns:
            self.db.execute(
                "ALTER TABLE queue ADD COLUMN result TEXT"
            )

        self.db.commit()

    # ---------------------------------------------------------
    # CREATE
    # ---------------------------------------------------------

    def add(
        self,
        description,
        role=None,
        parent_task_id=None,
    ):
        task_id = str(uuid.uuid4())

        self.db.execute(
            """
            INSERT INTO queue
            (
                id,
                description,
                status,
                created_at,
                role,
                parent_task_id
            )
            VALUES (?, ?, 'pending', ?, ?, ?)
            """,
            (
                task_id,
                description,
                datetime.now(timezone.utc).isoformat(),
                role,
                parent_task_id,
            ),
        )

        self.db.commit()

        return task_id

    # ---------------------------------------------------------
    # READ
    # ---------------------------------------------------------

    def all_tasks(self):
        return self.db.execute(
            """
            SELECT
                id,
                description,
                status,
                role,
                parent_task_id,
                result
            FROM queue
            ORDER BY created_at
            """
        ).fetchall()

    def get(self, task_id):
        row = self.db.execute(
            """
            SELECT
                id,
                description,
                status,
                worker,
                created_at,
                started_at,
                finished_at,
                role,
                parent_task_id,
                result
            FROM queue
            WHERE id = ?
            """,
            (task_id,),
        ).fetchone()

        return row

    def get_result(self, task_id):
        row = self.db.execute(
            """
            SELECT result
            FROM queue
            WHERE id = ?
            """,
            (task_id,),
        ).fetchone()

        if not row or row[0] is None:
            return None

        try:
            return json.loads(row[0])
        except json.JSONDecodeError:
            return row[0]

    # ---------------------------------------------------------
    # PENDING
    # ---------------------------------------------------------

    def pending(self, role=None):
        base = """
            SELECT
                q.id,
                q.description
            FROM queue q
            WHERE q.status = 'pending'
              AND (
                  q.parent_task_id IS NULL
                  OR EXISTS (
                      SELECT 1
                      FROM queue p
                      WHERE p.id = q.parent_task_id
                        AND p.status = 'completed'
                        AND p.result IS NOT NULL
                  )
              )
        """

        if role:
            return self.db.execute(
                base + """
                    AND q.role = ?
                    ORDER BY q.created_at
                """,
                (role,),
            ).fetchall()

        return self.db.execute(
            base + """
                ORDER BY q.created_at
            """
        ).fetchall()

    # ---------------------------------------------------------
    # CLAIM
    # ---------------------------------------------------------

    def claim(self, worker, role=None):
        self.db.execute("BEGIN IMMEDIATE")

        try:
            if role:
                row = self.db.execute(
                    """
                    SELECT
                        q.id,
                        q.description,
                        q.status,
                        q.worker,
                        q.created_at,
                        q.started_at,
                        q.finished_at,
                        q.role,
                        q.parent_task_id,
                        q.result
                    FROM queue q
                    WHERE q.status = 'pending'
                      AND q.role = ?
                      AND (
                          q.parent_task_id IS NULL
                          OR EXISTS (
                              SELECT 1
                              FROM queue p
                              WHERE p.id = q.parent_task_id
                                AND p.status = 'completed'
                                AND p.result IS NOT NULL
                          )
                      )
                    ORDER BY q.created_at
                    LIMIT 1
                    """,
                    (role,),
                ).fetchone()

            else:
                row = self.db.execute(
                    """
                    SELECT
                        q.id,
                        q.description,
                        q.status,
                        q.worker,
                        q.created_at,
                        q.started_at,
                        q.finished_at,
                        q.role,
                        q.parent_task_id,
                        q.result
                    FROM queue q
                    WHERE q.status = 'pending'
                      AND (
                          q.parent_task_id IS NULL
                          OR EXISTS (
                              SELECT 1
                              FROM queue p
                              WHERE p.id = q.parent_task_id
                                AND p.status = 'completed'
                                AND p.result IS NOT NULL
                          )
                      )
                    ORDER BY q.created_at
                    LIMIT 1
                    """
                ).fetchone()

            if not row:
                self.db.rollback()
                return None

            task_id = row[0]

            updated = self.db.execute(
                """
                UPDATE queue
                SET
                    status = 'running',
                    worker = ?,
                    started_at = ?
                WHERE id = ?
                  AND status = 'pending'
                """,
                (
                    worker,
                    datetime.now(timezone.utc).isoformat(),
                    task_id,
                ),
            ).rowcount

            if updated != 1:
                self.db.rollback()
                return None

            self.db.commit()

            return self.get(task_id)

        except Exception:
            self.db.rollback()
            raise

    # ---------------------------------------------------------
    # FINISH
    # ---------------------------------------------------------

    def finish(self, task_id, result=None):
        # A successful task MUST have a result.
        if result is None:
            raise ValueError(
                f"Cannot complete task {task_id}: result is None"
            )

        # Validate JSON serializability before touching the DB.
        try:
            result_json = json.dumps(
                result,
                ensure_ascii=False,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Cannot complete task {task_id}: "
                f"result is not JSON serializable: {exc}"
            ) from exc

        finished_at = datetime.now(timezone.utc).isoformat()

        updated = self.db.execute(
            """
            UPDATE queue
            SET
                status = 'completed',
                result = ?,
                finished_at = ?
            WHERE id = ?
              AND status = 'running'
            """,
            (
                result_json,
                finished_at,
                task_id,
            ),
        ).rowcount

        if updated != 1:
            self.db.rollback()
            raise RuntimeError(
                f"Cannot complete task {task_id}: "
                f"task is not in running state"
            )

        self.db.commit()

    # ---------------------------------------------------------
    # FAIL
    # ---------------------------------------------------------

    def fail(self, task_id, result=None):
        result_json = None

        if result is not None:
            try:
                result_json = json.dumps(
                    result,
                    ensure_ascii=False,
                )
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"Cannot fail task {task_id}: "
                    f"result is not JSON serializable: {exc}"
                ) from exc

        finished_at = datetime.now(timezone.utc).isoformat()

        updated = self.db.execute(
            """
            UPDATE queue
            SET
                status = 'failed',
                result = ?,
                finished_at = ?
            WHERE id = ?
              AND status = 'running'
            """,
            (
                result_json,
                finished_at,
                task_id,
            ),
        ).rowcount

        if updated != 1:
            self.db.rollback()
            raise RuntimeError(
                f"Cannot fail task {task_id}: "
                f"task is not in running state"
            )

        self.db.commit()
