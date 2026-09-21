import json
import sqlite3
import uuid
from datetime import datetime, timezone

from shared.result_codec import encode, decode
from pathlib import Path


DB_PATH = Path("/opt/agent-farm/data/agent_farm.db")


# Retention policy: queue history is a bounded operational cache. EvidenceLedger
# is the durable research memory. Never let agent-generated descriptions/results
# make SQLite grow without bound.
MAX_DESCRIPTION_BYTES = 4096
MAX_QUEUE_HISTORY = 2000


class TaskQueue:
    def __init__(self):
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)

        self.db = sqlite3.connect(
            DB_PATH,
            timeout=30,
            check_same_thread=False,
        )
        self.db.execute("PRAGMA busy_timeout=30000")

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

        if "planner_decision" not in columns:
            self.db.execute(
                "ALTER TABLE queue ADD COLUMN planner_decision TEXT"
            )

        if "planner_decided_at" not in columns:
            self.db.execute(
                "ALTER TABLE queue ADD COLUMN planner_decided_at TEXT"
            )

        if "information_gain" not in columns:
            self.db.execute(
                "ALTER TABLE queue ADD COLUMN information_gain REAL"
            )

        if "fingerprint" not in columns:
            self.db.execute(
                "ALTER TABLE queue ADD COLUMN fingerprint TEXT"
            )

        if "retry_count" not in columns:
            self.db.execute(
                """
                ALTER TABLE queue
                ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0
                """
            )

        self.db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_queue_parent_task_id
            ON queue(parent_task_id)
            """
        )

        self.db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_queue_status_planner_decision
            ON queue(status, planner_decision)
            """
        )

        self.db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_queue_role
            ON queue(role)
            """
        )

        self.db.commit()

    @staticmethod
    def _bounded_description(description):
        suffix = "\n...[truncated]"
        raw = str(description).encode("utf-8")
        if len(raw) <= MAX_DESCRIPTION_BYTES:
            return str(description)
        keep = max(0, MAX_DESCRIPTION_BYTES - len(suffix.encode("utf-8")))
        return raw[:keep].decode("utf-8", "ignore") + suffix

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

        if description is None:
            description = ""
        description = self._bounded_description(description)

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

    def has_tasks(self):
        """Return whether executable/live work exists.

        Completed history is retained for provenance and analytics, but it
        must not prevent the autonomous master from starting the next goal.
        """
        row = self.db.execute(
            """
            SELECT 1
            FROM queue
            WHERE status NOT IN ('completed', 'failed')
            LIMIT 1
            """
        ).fetchone()
        return row is not None

    def all_tasks(self):
        return self.db.execute(
            """
            SELECT
                id,
                description,
                status,
                role,
                parent_task_id,
                finished_at,
                result,
                planner_decision,
                planner_decided_at,
                information_gain,
                fingerprint
            FROM queue
            ORDER BY created_at
            """
        ).fetchall()

    def planning_tasks(self):
        """
        Load only tasks that can change planner state this cycle.

        Completed tasks that already have a child or a terminal planner
        decision are not candidates and their large result payloads never
        need to be read again.
        """
        return self.db.execute(
            """
            SELECT
                q.id,
                q.description,
                q.status,
                q.role,
                q.parent_task_id,
                q.finished_at,
                q.result,
                q.planner_decision,
                q.planner_decided_at,
                q.information_gain,
                q.fingerprint
            FROM queue q
            WHERE q.status = 'failed'

            UNION ALL

            SELECT
                q.id,
                q.description,
                q.status,
                q.role,
                q.parent_task_id,
                q.finished_at,
                q.result,
                q.planner_decision,
                q.planner_decided_at,
                q.information_gain,
                q.fingerprint
            FROM queue q
            WHERE q.status = 'completed'
              AND q.planner_decision IS NULL
              AND NOT EXISTS (
                  SELECT 1
                  FROM queue c
                  WHERE c.parent_task_id = q.id
              )

            UNION ALL

            SELECT
                q.id,
                q.description,
                q.status,
                q.role,
                q.parent_task_id,
                q.finished_at,
                q.result,
                q.planner_decision,
                q.planner_decided_at,
                q.information_gain,
                q.fingerprint
            FROM queue q
            WHERE q.status = 'completed'
              AND q.planner_decision IN (
                  'CONTINUE', 'REFINE', 'VERIFY', 'BRANCH', 'ESCALATE'
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM queue c
                  WHERE c.parent_task_id = q.id
              )
            """
        ).fetchall()

    def summary(self):
        statuses = self.db.execute(
            "SELECT status, COUNT(*) FROM queue GROUP BY status"
        ).fetchall()
        roles = self.db.execute(
            "SELECT role, COUNT(*) FROM queue WHERE role IS NOT NULL GROUP BY role"
        ).fetchall()
        decisions = self.db.execute(
            "SELECT planner_decision, COUNT(*) FROM queue "
            "WHERE planner_decision IS NOT NULL GROUP BY planner_decision"
        ).fetchall()
        total = self.db.execute(
            "SELECT COUNT(*) FROM queue"
        ).fetchone()[0]
        return total, statuses, roles, decisions

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

        return decode(row[0])

    def compact_completed_results(
        self,
        older_than_days=7,
        keep_ancestor_depth=4,
        limit=500,
    ):
        """
        Drop raw results that no longer belong to an active planner branch.

        EvidenceLedger is the durable evidence memory. Raw task results are
        retained only while they can still be needed by a live/pending branch
        or by the bounded recent planner context. This prevents completed
        history from becoming unbounded storage.
        """
        from datetime import timedelta

        if older_than_days < 0:
            raise ValueError("older_than_days must be >= 0")
        if keep_ancestor_depth < 0:
            raise ValueError("keep_ancestor_depth must be >= 0")
        if limit <= 0:
            return 0

        cutoff = (
            datetime.now(timezone.utc)
            - timedelta(days=older_than_days)
        ).isoformat()

        query = """
            WITH RECURSIVE frontier(id) AS (
                SELECT q.id
                FROM queue q
                WHERE q.status IN ('pending', 'running')
                   OR (
                       q.status = 'completed'
                       AND q.planner_decision IS NULL
                   )
                   OR (
                       q.status = 'completed'
                       AND q.planner_decision IN (
                           'CONTINUE', 'REFINE', 'VERIFY',
                           'BRANCH', 'ESCALATE'
                       )
                       AND NOT EXISTS (
                           SELECT 1
                           FROM queue c
                           WHERE c.parent_task_id = q.id
                       )
                   )
            ),
            ancestors(id, depth) AS (
                SELECT id, 0
                FROM frontier
                UNION
                SELECT q.parent_task_id, ancestors.depth + 1
                FROM queue q
                JOIN ancestors
                  ON ancestors.id = q.id
                WHERE q.parent_task_id IS NOT NULL
                  AND ancestors.depth < ?
            ),
            candidates AS (
                SELECT q.id
                FROM queue q
                LEFT JOIN ancestors a
                  ON a.id = q.id
                WHERE q.status = 'completed'
                  AND q.result IS NOT NULL
                  AND q.finished_at IS NOT NULL
                  AND q.finished_at < ?
                  AND a.id IS NULL
                LIMIT ?
            )
            UPDATE queue
            SET result = NULL
            WHERE id IN (SELECT id FROM candidates)
        """

        self.db.execute(
            query,
            (
                int(keep_ancestor_depth),
                cutoff,
                int(limit),
            ),
        )
        updated = self.db.execute(
            "SELECT changes()"
        ).fetchone()[0]

        if updated:
            self.db.commit()

        return max(0, int(updated or 0))

    def compact_history(self, keep_recent=MAX_QUEUE_HISTORY, limit=1000):
        """Bound completed/failed queue history without touching live work.

        Recent rows are retained for operational context. Older historical
        rows are disposable because durable findings live in EvidenceLedger.
        """
        keep_recent = int(keep_recent)
        limit = int(limit)
        if keep_recent <= 0 or limit <= 0:
            return 0

        rows = self.db.execute(
            "SELECT id, description FROM queue"
        ).fetchall()
        for task_id, description in rows:
            bounded = self._bounded_description(description)
            if bounded != description:
                self.db.execute(
                    "UPDATE queue SET description = ? WHERE id = ?",
                    (bounded, task_id),
                )
        self.db.commit()

        ids = [row[0] for row in self.db.execute(
            "SELECT id FROM queue WHERE status IN ('completed','failed') "
            "ORDER BY COALESCE(finished_at,created_at) DESC,id DESC LIMIT ?",
            (keep_recent,),
        ).fetchall()]
        if not ids:
            return 0

        placeholders = ",".join("?" for _ in ids)
        candidates = self.db.execute(
            f"SELECT id FROM queue WHERE status IN ('completed','failed') "
            f"AND id NOT IN ({placeholders}) LIMIT ?",
            (*ids, limit),
        ).fetchall()
        candidate_ids = [row[0] for row in candidates]
        if not candidate_ids:
            return 0

        placeholders = ",".join("?" for _ in candidate_ids)
        removable = self.db.execute(
            f"SELECT q.id FROM queue q WHERE q.id IN ({placeholders}) "
            f"AND NOT EXISTS (SELECT 1 FROM queue child "
            f"WHERE child.parent_task_id=q.id AND child.id NOT IN ({placeholders}))",
            (*candidate_ids, *candidate_ids),
        ).fetchall()
        removable_ids = [row[0] for row in removable]
        if not removable_ids:
            return 0

        placeholders = ",".join("?" for _ in removable_ids)
        self.db.execute(
            f"DELETE FROM queue WHERE id IN ({placeholders})",
            removable_ids,
        )
        deleted = int(self.db.execute("SELECT changes()").fetchone()[0] or 0)
        if deleted:
            self.db.commit()
        return deleted

    # ---------------------------------------------------------
    # MASTER PLANNER STATE
    # ---------------------------------------------------------

    def mark_planner_decision(
        self,
        task_id,
        decision,
        information_gain=0.0,
        fingerprint=None,
    ):
        self.db.execute(
            """
            UPDATE queue
            SET
                planner_decision = ?,
                planner_decided_at = ?,
                information_gain = ?,
                fingerprint = ?
            WHERE id = ?
            """,
            (
                decision,
                datetime.now(timezone.utc).isoformat(),
                float(information_gain),
                fingerprint,
                task_id,
            ),
        )
        self.db.commit()

    def planner_processed(self, task_id):
        row = self.db.execute(
            """
            SELECT planner_decision
            FROM queue
            WHERE id = ?
            """,
            (task_id,),
        ).fetchone()

        return bool(row and row[0])

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
    # DAG INTEGRITY
    # ---------------------------------------------------------

    def active_orphans(self):
        """
        Return active tasks whose parent_task_id points to a
        non-existent task.

        Historical failed orphan tasks are intentionally excluded.
        They remain in the database for auditability.
        """
        return self.db.execute(
            """
            SELECT
                q.id,
                q.description,
                q.status,
                q.role,
                q.parent_task_id
            FROM queue q
            LEFT JOIN queue p
                ON p.id = q.parent_task_id
            WHERE q.parent_task_id IS NOT NULL
              AND p.id IS NULL
              AND q.status IN ('pending', 'running')
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
    # WORKER RECOVERY
    # ---------------------------------------------------------

    @staticmethod
    def _worker_pid(worker):
        if not worker:
            return None

        try:
            return int(str(worker).rsplit("-", 1)[-1])
        except (TypeError, ValueError):
            return None

    @classmethod
    def _worker_alive(cls, worker):
        pid = cls._worker_pid(worker)

        if pid is None or pid <= 0:
            return False

        try:
            import os
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False

    def recover_stale_running(self, stale_minutes=10):
        """
        Requeue running tasks whose worker process no longer exists.

        A live worker is never requeued just because the task is old.
        """
        from datetime import timedelta

        cutoff = datetime.now(timezone.utc) - timedelta(
            minutes=stale_minutes
        )

        rows = self.db.execute(
            """
            SELECT id, worker, started_at
            FROM queue
            WHERE status = 'running'
              AND started_at IS NOT NULL
            ORDER BY started_at
            """
        ).fetchall()

        recovered = []

        for task_id, worker, started_at in rows:
            try:
                started = datetime.fromisoformat(started_at)
            except (TypeError, ValueError):
                continue

            if started > cutoff:
                continue

            if self._worker_alive(worker):
                continue

            updated = self.db.execute(
                """
                UPDATE queue
                SET
                    status = 'pending',
                    worker = NULL,
                    started_at = NULL
                WHERE id = ?
                  AND status = 'running'
                """,
                (task_id,),
            ).rowcount

            if updated == 1:
                recovered.append(task_id)

        if recovered:
            self.db.commit()

        return recovered

    # ---------------------------------------------------------
    # FAILURE RECOVERY
    # ---------------------------------------------------------

    def retry_count(self, task_id):
        row = self.db.execute(
            """
            SELECT retry_count
            FROM queue
            WHERE id = ?
            """,
            (task_id,),
        ).fetchone()

        if not row:
            return 0

        return int(row[0] or 0)

    def requeue_failed(self, task_id, max_retries=3):
        """
        Requeue one failed task for another attempt.

        The parent task must still be completed. The previous failure
        result remains stored for auditability until the worker produces
        a new result.
        """
        row = self.db.execute(
            """
            SELECT status, retry_count, parent_task_id
            FROM queue
            WHERE id = ?
            """,
            (task_id,),
        ).fetchone()

        if not row:
            return False

        status, retry_count, parent_task_id = row

        if status != "failed":
            return False

        retry_count = int(retry_count or 0)

        if retry_count >= max_retries:
            return False

        if parent_task_id:
            parent = self.db.execute(
                """
                SELECT status, result
                FROM queue
                WHERE id = ?
                """,
                (parent_task_id,),
            ).fetchone()

            if not parent:
                return False

            parent_status, parent_result = parent

            if (
                parent_status != "completed"
                or parent_result is None
            ):
                return False

        updated = self.db.execute(
            """
            UPDATE queue
            SET
                status = 'pending',
                worker = NULL,
                started_at = NULL,
                finished_at = NULL,
                retry_count = retry_count + 1
            WHERE id = ?
              AND status = 'failed'
            """,
            (task_id,),
        ).rowcount

        if updated != 1:
            self.db.rollback()
            return False

        self.db.commit()

        return True

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
            result_json = encode(result)
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
                result_json = encode(result)
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
