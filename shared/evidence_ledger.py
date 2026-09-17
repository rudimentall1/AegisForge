import hashlib
import json
from datetime import datetime, timezone


class EvidenceLedger:
    """Persistent normalized evidence with bounded provenance per observation."""

    def __init__(self, db):
        self.db = db
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS evidence_ledger (
                atom_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                value TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                confirmation_count INTEGER NOT NULL DEFAULT 0,
                independent_role_count INTEGER NOT NULL DEFAULT 0,
                latest_task_id TEXT,
                latest_role TEXT
            )
        """)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS evidence_observations (
                atom_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                role TEXT,
                observed_at TEXT NOT NULL,
                PRIMARY KEY (atom_id, task_id)
            )
        """)
        self.db.execute("""
            CREATE INDEX IF NOT EXISTS idx_evidence_last_seen
            ON evidence_ledger(last_seen)
        """)
        self.db.execute("""
            CREATE INDEX IF NOT EXISTS idx_evidence_observation_task
            ON evidence_observations(task_id)
        """)
        self.db.commit()

    @staticmethod
    def atom_id(atom):
        return hashlib.sha256(atom.encode("utf-8")).hexdigest()

    @staticmethod
    def split_atom(atom):
        kind, sep, value = str(atom).partition(":")
        return kind if sep else "unknown", value if sep else str(atom)

    def record(self, task_id, role, atoms, observed_at=None):
        if not task_id or not atoms:
            return {"inserted": 0, "confirmed": 0}

        now = observed_at or datetime.now(timezone.utc).isoformat()
        inserted = 0
        confirmed = 0

        for atom in sorted(set(atoms)):
            atom = str(atom).strip()
            if not atom:
                continue

            atom_id = self.atom_id(atom)
            kind, value = self.split_atom(atom)
            exists = self.db.execute(
                "SELECT 1 FROM evidence_ledger WHERE atom_id = ?",
                (atom_id,),
            ).fetchone()

            inserted_observation = self.db.execute(
                "INSERT OR IGNORE INTO evidence_observations "
                "(atom_id, task_id, role, observed_at) VALUES (?, ?, ?, ?)",
                (atom_id, task_id, role, now),
            ).rowcount

            if exists:
                if inserted_observation:
                    confirmed += 1
                self.db.execute(
                    """UPDATE evidence_ledger
                       SET last_seen = ?, latest_task_id = ?, latest_role = ?,
                           confirmation_count = confirmation_count + ?,
                           independent_role_count = (
                               SELECT COUNT(DISTINCT role)
                               FROM evidence_observations
                               WHERE atom_id = ? AND role IS NOT NULL
                           )
                       WHERE atom_id = ?""",
                    (now, task_id, role, int(bool(inserted_observation)), atom_id, atom_id),
                )
            else:
                inserted += 1
                self.db.execute(
                    """INSERT INTO evidence_ledger
                       (atom_id, kind, value, first_seen, last_seen,
                        confirmation_count, independent_role_count,
                        latest_task_id, latest_role)
                       VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)""",
                    (atom_id, kind, value, now, now,
                     1 if role else 0, task_id, role),
                )

        self.db.commit()
        return {"inserted": inserted, "confirmed": confirmed}

    def stats(self):
        row = self.db.execute(
            "SELECT COUNT(*), COALESCE(SUM(confirmation_count), 0) "
            "FROM evidence_ledger"
        ).fetchone()
        return {"atoms": row[0], "confirmations": row[1]}
