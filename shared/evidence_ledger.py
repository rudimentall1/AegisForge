import hashlib
from datetime import datetime, timezone


class EvidenceLedger:
    """Persistent normalized evidence with bounded provenance."""

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
            CREATE TABLE IF NOT EXISTS evidence_provenance (
                atom_id TEXT NOT NULL,
                role TEXT NOT NULL,
                first_task_id TEXT NOT NULL,
                latest_task_id TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                observation_count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (atom_id, role)
            )
        """)
        self.db.execute("""
            CREATE INDEX IF NOT EXISTS idx_evidence_last_seen
            ON evidence_ledger(last_seen)
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
        if not role:
            role = "unknown"
        now = observed_at or datetime.now(timezone.utc).isoformat()
        inserted = 0
        confirmed = 0

        for atom in sorted(set(atoms)):
            atom = str(atom).strip()
            if not atom:
                continue
            atom_id = self.atom_id(atom)
            kind, value = self.split_atom(atom)
            row = self.db.execute(
                "SELECT confirmation_count FROM evidence_ledger WHERE atom_id = ?",
                (atom_id,),
            ).fetchone()
            provenance = self.db.execute(
                "SELECT observation_count FROM evidence_provenance "
                "WHERE atom_id = ? AND role = ?",
                (atom_id, role),
            ).fetchone()

            if row is None:
                inserted += 1
                self.db.execute(
                    """INSERT INTO evidence_ledger
                       (atom_id, kind, value, first_seen, last_seen,
                        confirmation_count, independent_role_count,
                        latest_task_id, latest_role)
                       VALUES (?, ?, ?, ?, ?, 1, 1, ?, ?)""",
                    (atom_id, kind, value, now, now, task_id, role),
                )
            elif provenance is None:
                confirmed += 1
                self.db.execute(
                    """UPDATE evidence_ledger
                       SET last_seen = ?, latest_task_id = ?, latest_role = ?,
                           confirmation_count = confirmation_count + 1,
                           independent_role_count = independent_role_count + 1
                       WHERE atom_id = ?""",
                    (now, task_id, role, atom_id),
                )
            else:
                self.db.execute(
                    """UPDATE evidence_ledger
                       SET last_seen = ?, latest_task_id = ?, latest_role = ?,
                           confirmation_count = confirmation_count + 1
                       WHERE atom_id = ?""",
                    (now, task_id, role, atom_id),
                )

            if provenance is None:
                self.db.execute(
                    """INSERT INTO evidence_provenance
                       (atom_id, role, first_task_id, latest_task_id,
                        first_seen, last_seen, observation_count)
                       VALUES (?, ?, ?, ?, ?, ?, 1)""",
                    (atom_id, role, task_id, task_id, now, now),
                )
            else:
                self.db.execute(
                    """UPDATE evidence_provenance
                       SET latest_task_id = ?, last_seen = ?,
                           observation_count = observation_count + 1
                       WHERE atom_id = ? AND role = ?""",
                    (task_id, now, atom_id, role),
                )

        self.db.commit()
        return {"inserted": inserted, "confirmed": confirmed}

    def stats(self):
        row = self.db.execute(
            "SELECT COUNT(*), COALESCE(SUM(confirmation_count), 0) "
            "FROM evidence_ledger"
        ).fetchone()
        return {"atoms": row[0], "confirmations": row[1]}
