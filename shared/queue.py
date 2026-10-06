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
MAX_QUEUE_HISTORY = 500
MAX_CAPABILITY_INTENT_BYTES = 8192


class TaskQueue:
    def __init__(self, db_path=None):
        path = Path(db_path) if db_path else DB_PATH
        path.parent.mkdir(parents=True, exist_ok=True)

        self.db = sqlite3.connect(
            path,
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

        if "capability_intent" not in columns:
            self.db.execute(
                "ALTER TABLE queue ADD COLUMN capability_intent TEXT"
            )

        if "allow_failed_parent" not in columns:
            self.db.execute(
                "ALTER TABLE queue ADD COLUMN allow_failed_parent INTEGER NOT NULL DEFAULT 0"
            )

        for column, sql_type in (
            ("action_role", "TEXT"),
            ("expected_evidence_gain", "REAL"),
            ("raw_expected_evidence_gain", "REAL"),
            ("action_cost", "REAL"),
            ("action_efficiency", "REAL"),
        ):
            if column not in columns:
                self.db.execute(
                    f"ALTER TABLE queue ADD COLUMN {column} {sql_type}"
                )

        self.db.execute("""
            CREATE TABLE IF NOT EXISTS execution_outcome_feedback (
                execution_task_id TEXT PRIMARY KEY,
                origin_task_id TEXT,
                action_role TEXT,
                status TEXT NOT NULL,
                verifier TEXT,
                outcome_id TEXT,
                receipt_id TEXT,
                observed_at TEXT NOT NULL
            )
        """)

        self.db.execute("""
            CREATE TABLE IF NOT EXISTS planner_action_outcomes (
                child_task_id TEXT PRIMARY KEY,
                parent_task_id TEXT NOT NULL,
                action_role TEXT,
                expected_evidence_gain REAL NOT NULL,
                action_cost REAL NOT NULL,
                action_efficiency REAL NOT NULL,
                actual_evidence_gain REAL NOT NULL,
                novelty REAL NOT NULL,
                novel_atom_count INTEGER NOT NULL,
                atom_count INTEGER NOT NULL,
                prediction_error REAL NOT NULL,
                observed_at TEXT NOT NULL,
                metric_version INTEGER NOT NULL DEFAULT 1
            )
        """)

        outcome_columns = {
            row[1] for row in self.db.execute(
                "PRAGMA table_info(planner_action_outcomes)"
            ).fetchall()
        }
        if "metric_version" not in outcome_columns:
            self.db.execute(
                "ALTER TABLE planner_action_outcomes "
                "ADD COLUMN metric_version INTEGER NOT NULL DEFAULT 1"
            )
        self.db.execute("""
            CREATE INDEX IF NOT EXISTS idx_planner_action_outcomes_observed
            ON planner_action_outcomes(observed_at)
        """)
        self.db.execute("""
            CREATE INDEX IF NOT EXISTS idx_planner_action_outcomes_role_metric
            ON planner_action_outcomes(action_role, metric_version, observed_at)
        """)

        self.db.execute("""
            CREATE TABLE IF NOT EXISTS planner_decision_traces (
                id TEXT PRIMARY KEY,
                task_id TEXT,
                source_role TEXT,
                candidate_role TEXT NOT NULL,
                decision TEXT NOT NULL,
                raw_expected_gain REAL NOT NULL,
                expected_evidence_gain REAL NOT NULL,
                action_cost REAL NOT NULL,
                efficiency REAL NOT NULL,
                selected INTEGER NOT NULL,
                selection_rank INTEGER NOT NULL,
                observed_at TEXT NOT NULL
            )
        """)
        self.db.execute("""
            CREATE INDEX IF NOT EXISTS idx_planner_decision_traces_task
            ON planner_decision_traces(task_id, observed_at)
        """)

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
        capability_intent=None,
        allow_failed_parent=False,
    ):
        task_id = str(uuid.uuid4())

        if description is None:
            description = ""
        description = self._bounded_description(description)

        intent_json = None
        if capability_intent is not None:
            if not isinstance(capability_intent, dict):
                raise TypeError("capability_intent must be a dict or None")
            intent_json = json.dumps(
                capability_intent,
                sort_keys=True,
                separators=(",", ":"),
            )
            if len(intent_json.encode("utf-8")) > MAX_CAPABILITY_INTENT_BYTES:
                raise ValueError("capability_intent exceeds bounded storage size")

        self.db.execute(
            """
            INSERT INTO queue
            (
                id,
                description,
                status,
                created_at,
                role,
                parent_task_id,
                capability_intent,
                allow_failed_parent
            )
            VALUES (?, ?, 'pending', ?, ?, ?, ?, ?)
            """,
            (
                task_id,
                description,
                datetime.now(timezone.utc).isoformat(),
                role,
                parent_task_id,
                intent_json,
                1 if allow_failed_parent else 0,
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

    def has_planner_work(self):
        """Return whether Master still has work to process before bootstrapping.

        A worker can finish a task between Master cycles. Such a task is no
        longer "live", but it is still actionable until the planner records a
        decision. Treating it as idle would inject a fresh researcher root and
        create an artificial discovery loop.
        """
        row = self.db.execute(
            """
            SELECT 1
            FROM queue
            WHERE status NOT IN ('completed', 'failed')
               OR (status = 'completed' AND result IS NOT NULL
                   AND planner_decision IS NULL)
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
                result,
                capability_intent,
                allow_failed_parent
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
        # Never delete an ancestor of a retained/live task. A prior version
        # could delete a parent in one compaction batch while its child
        # survived, creating an executable orphan that workers could never claim.
        protected = set()
        frontier = [row[0] for row in self.db.execute(
            f"SELECT id FROM queue WHERE id NOT IN ({placeholders})",
            candidate_ids,
        ).fetchall()]
        while frontier:
            chunk = frontier[:500]
            frontier = frontier[500:]
            ph = ",".join("?" for _ in chunk)
            parents = [r[0] for r in self.db.execute(
                f"SELECT parent_task_id FROM queue WHERE id IN ({ph}) "
                "AND parent_task_id IS NOT NULL",
                chunk,
            ).fetchall()]
            for parent in parents:
                if parent not in protected:
                    protected.add(parent)
                    frontier.append(parent)

        removable_ids = [
            row for row in candidate_ids
            if row not in protected
        ]
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
        action_role=None,
        expected_evidence_gain=0.0,
        action_cost=0.0,
        action_efficiency=0.0,
        raw_expected_evidence_gain=None,
    ):
        self.db.execute(
            """
            UPDATE queue
            SET
                planner_decision = ?,
                planner_decided_at = ?,
                information_gain = ?,
                fingerprint = ?,
                action_role = ?,
                expected_evidence_gain = ?,
                raw_expected_evidence_gain = ?,
                action_cost = ?,
                action_efficiency = ?
            WHERE id = ?
            """,
            (
                decision,
                datetime.now(timezone.utc).isoformat(),
                float(information_gain),
                fingerprint,
                action_role,
                float(expected_evidence_gain or 0.0),
                float(raw_expected_evidence_gain if raw_expected_evidence_gain is not None else expected_evidence_gain or 0.0),
                float(action_cost or 0.0),
                float(action_efficiency or 0.0),
                task_id,
            ),
        )
        self.db.commit()

    def record_action_outcome(
        self,
        child_task_id,
        actual_evidence_gain,
        novelty,
        novel_atom_count,
        atom_count,
        observed_at=None,
        max_rows=200,
    ):
        """Record bounded feedback for a planner action once its child completes."""
        # Attribution is a cross-process critical section: two master/worker
        # paths can finish descendants at nearly the same time. Serialize the
        # parent lookup + deduplication + insert so exactly one logical planner
        # action becomes a calibration sample and duplicate writers are a safe
        # no-op rather than a PRIMARY KEY race on child_task_id.
        self.db.execute("BEGIN IMMEDIATE")
        try:
            current_id = child_task_id
            origin = None
            while current_id:
                current = self.db.execute(
                    """
                    SELECT id, parent_task_id, action_role, expected_evidence_gain,
                           action_cost, action_efficiency, status
                    FROM queue WHERE id = ?
                    """,
                    (current_id,),
                ).fetchone()
                if current is None:
                    break
                if current[2]:
                    origin = current
                    break
                current_id = current[1]

            if origin is None:
                self.db.rollback()
                return False

            # The planner action itself may remain pending while its descendant
            # completes, so its status is intentionally not used as a gate.

            # One calibration sample belongs to one logical planner action, not
            # to every validator/executor descendant in its provenance chain.
            existing = self.db.execute(
                "SELECT 1 FROM planner_action_outcomes WHERE parent_task_id = ?",
                (origin[0],),
            ).fetchone()
            if existing:
                self.db.rollback()
                return False

            row = origin

            actual = max(0.0, min(1.0, float(actual_evidence_gain)))
            expected = max(0.0, min(1.0, float(row[3] or 0.0)))
            now = observed_at or datetime.now(timezone.utc).isoformat()
            self.db.execute(
                """
                INSERT INTO planner_action_outcomes
                (child_task_id, parent_task_id, action_role, expected_evidence_gain,
                 action_cost, action_efficiency, actual_evidence_gain, novelty,
                 novel_atom_count, atom_count, prediction_error, observed_at, metric_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 2)
                """,
                (
                    child_task_id, row[0], row[2], expected, float(row[4] or 0.0),
                    float(row[5] or 0.0), actual, max(0.0, min(1.0, float(novelty))),
                    int(novel_atom_count), int(atom_count), actual - expected, now,
                ),
            )
            self.db.execute(
                """
                DELETE FROM planner_action_outcomes
                WHERE child_task_id IN (
                    SELECT child_task_id FROM planner_action_outcomes
                    ORDER BY observed_at DESC
                    LIMIT -1 OFFSET ?
                )
                """,
                (int(max_rows),),
            )
            self.db.commit()
            return True
        except Exception:
            self.db.rollback()
            raise

    def record_verified_outcome_feedback(
        self,
        descendant_task_id,
        status,
        verifier=None,
        outcome_id=None,
        receipt_id=None,
        observed_at=None,
    ):
        """Feed a verified execution outcome back to its originating planner action.

        The execution task may be nested below validator/handoff tasks, so walk
        ancestors until the planner action carrying action_role is found.
        Only a PROVEN outcome creates positive evidence feedback.
        """
        current_id = descendant_task_id
        origin = None
        while current_id:
            row = self.db.execute(
                "SELECT id, parent_task_id, action_role, status FROM queue WHERE id = ?",
                (current_id,),
            ).fetchone()
            if row is None:
                break
            if row[2]:
                origin = row
                break
            current_id = row[1]

        if origin is None or str(status).upper() != "PROVEN":
            return False

        now = observed_at or datetime.now(timezone.utc).isoformat()
        existing = self.db.execute(
            "SELECT 1 FROM execution_outcome_feedback WHERE execution_task_id = ?",
            (descendant_task_id,),
        ).fetchone()
        if existing:
            return False

        self.db.execute(
            """
            INSERT INTO execution_outcome_feedback
            (execution_task_id, origin_task_id, action_role, status,
             verifier, outcome_id, receipt_id, observed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                descendant_task_id,
                origin[0],
                origin[2],
                str(status).upper(),
                verifier,
                outcome_id,
                receipt_id,
                now,
            ),
        )
        self.db.commit()
        return True

    def record_planner_decision_trace(self, task_id, source_role, candidates, observed_at=None):
        """Persist candidate economics without changing planner policy."""
        if not candidates:
            return 0

        now = observed_at or datetime.now(timezone.utc).isoformat()
        rows = []
        for rank, item in enumerate(candidates, start=1):
            rows.append((
                str(uuid.uuid4()),
                task_id,
                source_role,
                item.get("candidate_role") or "unknown",
                item.get("decision") or "",
                float(item.get("raw_expected_gain", 0.0)),
                float(item.get("expected_evidence_gain", 0.0)),
                float(item.get("cost", 0.0)),
                float(item.get("efficiency", 0.0)),
                1 if item.get("selected") else 0,
                rank,
                now,
            ))

        self.db.executemany(
            """
            INSERT INTO planner_decision_traces
            (id, task_id, source_role, candidate_role, decision,
             raw_expected_gain, expected_evidence_gain, action_cost, efficiency,
             selected, selection_rank, observed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        self.db.commit()
        return len(rows)

    def action_outcome_summary(self, limit=200, metric_version=2):
        rows = self.db.execute(
            """
            SELECT action_role, expected_evidence_gain, actual_evidence_gain,
                   prediction_error, action_cost
            FROM planner_action_outcomes
            WHERE metric_version = ?
            ORDER BY observed_at DESC LIMIT ?
            """,
            (int(metric_version), int(limit)),
        ).fetchall()
        if not rows:
            return {
                "metric_version": int(metric_version),
                "samples": 0,
                "mae": 0.0,
                "bias": 0.0,
                "by_role": {},
            }

        errors = [float(r[3]) for r in rows]
        by = {}
        for role, expected, actual, error, cost in rows:
            role = role or "unknown"
            x = by.setdefault(
                role,
                {
                    "samples": 0,
                    "expected": 0.0,
                    "actual": 0.0,
                    "cost": 0.0,
                    "relative_ratio": 0.0,
                    "ratio_samples": 0,
                },
            )
            x["samples"] += 1
            x["expected"] += float(expected)
            x["actual"] += float(actual)
            x["cost"] += float(cost)
            expected_value = float(expected or 0.0)
            if expected_value > 0.05:
                ratio = max(0.0, min(1.5, float(actual) / expected_value))
                x["relative_ratio"] += ratio
                x["ratio_samples"] += 1

        for x in by.values():
            n = x["samples"]
            x["expected"] = round(x["expected"] / n, 4)
            x["actual"] = round(x["actual"] / n, 4)
            x["cost"] = round(x["cost"] / n, 4)
            ratio_samples = x.pop("ratio_samples", 0)
            x["relative_ratio"] = (
                round(x["relative_ratio"] / ratio_samples, 4)
                if ratio_samples
                else 1.0
            )

        return {
            "metric_version": int(metric_version),
            "samples": len(rows),
            "mae": round(sum(abs(x) for x in errors) / len(errors), 4),
            "bias": round(sum(errors) / len(errors), 4),
            "by_role": by,
        }

    def action_calibration(
        self,
        action_role,
        source_role=None,
        min_samples=3,
        full_samples=10,
        max_adjustment=0.25,
    ):
        """Return conservative calibration, preferring source->action context."""
        role = str(action_role or "unknown")
        source = str(source_role or "").strip() or None
        metric_version = 2

        def _rows_for_signature(signature_role=None):
            if signature_role:
                return self.db.execute(
                    """
                    SELECT COALESCE(p.raw_expected_evidence_gain, o.expected_evidence_gain),
                           o.actual_evidence_gain
                    FROM planner_action_outcomes o
                    JOIN queue p ON p.id = o.parent_task_id
                    WHERE o.action_role = ?
                      AND p.role = ?
                      AND o.metric_version = ?
                    ORDER BY o.observed_at DESC
                    LIMIT 200
                    """,
                    (role, signature_role, metric_version),
                ).fetchall()
            return self.db.execute(
                """
                SELECT COALESCE(p.raw_expected_evidence_gain, o.expected_evidence_gain),
                       o.actual_evidence_gain
                FROM planner_action_outcomes o
                LEFT JOIN queue p ON p.id = o.parent_task_id
                WHERE o.action_role = ?
                  AND o.metric_version = ?
                ORDER BY o.observed_at DESC
                LIMIT 200
                """,
                (role, metric_version),
            ).fetchall()

        signature_rows = _rows_for_signature(source) if source else []
        role_rows = _rows_for_signature(None)
        if source and len(signature_rows) >= int(min_samples):
            rows = signature_rows
            scope = "signature"
        else:
            rows = role_rows
            scope = "role"

        samples = len(rows)
        signature_samples = len(signature_rows) if source else 0
        role_samples = len(role_rows)
        if samples < int(min_samples):
            return {
                "factor": 1.0,
                "samples": samples,
                "raw_ratio": 1.0,
                "weight": 0.0,
                "scope": scope,
                "signature_samples": signature_samples,
                "role_samples": role_samples,
            }

        ratios = []
        for expected, actual in rows:
            expected_value = float(expected or 0.0)
            if expected_value <= 0.05:
                continue
            ratio = max(0.0, min(1.5, float(actual or 0.0) / expected_value))
            ratios.append(ratio)

        if not ratios:
            return {
                "factor": 1.0,
                "samples": samples,
                "raw_ratio": 1.0,
                "weight": 0.0,
                "scope": scope,
                "signature_samples": signature_samples,
                "role_samples": role_samples,
            }

        raw_ratio = sum(ratios) / len(ratios)
        ramp = max(1, int(full_samples) - int(min_samples) + 1)
        weight = min(1.0, max(0.0, samples - int(min_samples) + 1) / ramp)
        adjustment = max(
            -float(max_adjustment),
            min(float(max_adjustment), (raw_ratio - 1.0) * weight),
        )
        factor = 1.0 + adjustment
        return {
            "factor": round(factor, 4),
            "samples": samples,
            "raw_ratio": round(raw_ratio, 4),
            "weight": round(weight, 4),
            "scope": scope,
            "signature_samples": signature_samples,
            "role_samples": role_samples,
        }

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

    def repair_active_orphans(self):
        """Remove pending orphan subtrees created by legacy/partial DAG writes."""
        roots = [r[0] for r in self.active_orphans()]
        if not roots:
            return 0
        placeholders = ",".join("?" for _ in roots)
        self.db.execute(
            f"""WITH RECURSIVE doomed(id) AS (
                SELECT id FROM queue WHERE id IN ({placeholders}) AND status='pending'
                UNION ALL
                SELECT q.id FROM queue q JOIN doomed d ON q.parent_task_id=d.id
                WHERE q.status='pending'
            )
            DELETE FROM queue WHERE id IN doomed""",
            roots,
        )
        deleted = int(self.db.execute("SELECT changes()").fetchone()[0] or 0)
        if deleted:
            self.db.commit()
        return deleted

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
                        q.result,
                        q.capability_intent,
                        q.allow_failed_parent
                    FROM queue q
                    WHERE q.status = 'pending'
                      AND q.role = ?
                      AND (
                          q.parent_task_id IS NULL
                          OR q.allow_failed_parent = 1
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
                        q.result,
                        q.capability_intent,
                        q.allow_failed_parent
                    FROM queue q
                    WHERE q.status = 'pending'
                      AND (
                          q.parent_task_id IS NULL
                          OR q.allow_failed_parent = 1
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
            SELECT status, retry_count, parent_task_id, allow_failed_parent
            FROM queue
            WHERE id = ?
            """,
            (task_id,),
        ).fetchone()

        if not row:
            return False

        status, retry_count, parent_task_id, allow_failed_parent = row

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

            parent_ready = (
                parent_status == "completed"
                and parent_result is not None
            )
            failed_parent_ready = (
                parent_status == "failed"
                and bool(allow_failed_parent)
                and parent_result is not None
            )
            if not (parent_ready or failed_parent_ready):
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