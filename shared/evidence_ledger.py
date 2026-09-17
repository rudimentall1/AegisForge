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
        contradictions = self.detect_contradictions(atoms)
        contradiction_count = self.record_contradictions(
            task_id, role, contradictions, observed_at=now
        )
        self.last_contradiction_count = contradiction_count
        return {"inserted": inserted, "confirmed": confirmed}

    @staticmethod
    def _finding_identity(finding):
        if not isinstance(finding, dict):
            return None
        identity = {}
        for key in ("repository", "file", "rule", "description", "contract", "address"):
            value = finding.get(key)
            if value is not None and str(value).strip():
                identity[key] = str(value).strip()
        return tuple(sorted(identity.items())) if identity else None

    @staticmethod
    def _finding_status(finding):
        if not isinstance(finding, dict):
            return None
        for key in ("status", "verdict", "result"):
            value = finding.get(key)
            if value is not None and str(value).strip():
                return str(value).strip().upper()
        return None

    def detect_contradictions(self, atoms):
        """Detect explicit contradictions without treating refinements as conflicts."""
        findings = []
        for atom in sorted(set(atoms or ())):
            kind, value = self.split_atom(atom)
            if kind != "finding":
                continue
            try:
                finding = __import__("json").loads(value)
            except Exception:
                continue
            identity = self._finding_identity(finding)
            status = self._finding_status(finding)
            if identity and status:
                findings.append((self.atom_id(atom), identity, status))

        if not findings:
            return []

        existing = self.db.execute(
            "SELECT atom_id, value FROM evidence_ledger WHERE kind = 'finding'"
        ).fetchall()
        opposite = {
            "POTENTIAL_RISK": {"SAFE", "NOT_A_RISK", "FALSE_POSITIVE", "REJECTED"},
            "CONFIRMED": {"SAFE", "NOT_A_RISK", "FALSE_POSITIVE", "REJECTED"},
            "SAFE": {"POTENTIAL_RISK", "CONFIRMED"},
            "NOT_A_RISK": {"POTENTIAL_RISK", "CONFIRMED"},
            "FALSE_POSITIVE": {"POTENTIAL_RISK", "CONFIRMED"},
            "REJECTED": {"POTENTIAL_RISK", "CONFIRMED"},
        }
        conflicts = []
        for atom_id, identity, status in findings:
            for existing_id, value in existing:
                if existing_id == atom_id:
                    continue
                try:
                    old = __import__("json").loads(value)
                except Exception:
                    continue
                old_identity = self._finding_identity(old)
                old_status = self._finding_status(old)
                if old_identity == identity and old_status in opposite.get(status, set()):
                    pair = tuple(sorted((atom_id, existing_id)))
                    if pair not in {(c["atom_id"], c["other_atom_id"]) for c in conflicts}:
                        conflicts.append({
                            "atom_id": pair[0],
                            "other_atom_id": pair[1],
                            "reason": f"same finding identity with contradictory status: {status} vs {old_status}",
                        })
        return conflicts

    def record_contradictions(self, task_id, role, contradictions, observed_at=None):
        if not contradictions:
            return 0
        now = observed_at or datetime.now(timezone.utc).isoformat()
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS evidence_contradictions (
                atom_id TEXT NOT NULL,
                other_atom_id TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                first_task_id TEXT NOT NULL,
                latest_task_id TEXT NOT NULL,
                latest_role TEXT NOT NULL,
                reason TEXT NOT NULL,
                PRIMARY KEY (atom_id, other_atom_id)
            )
        """)
        count = 0
        for item in contradictions:
            a, b = item["atom_id"], item["other_atom_id"]
            self.db.execute("""
                INSERT INTO evidence_contradictions
                (atom_id, other_atom_id, first_seen, last_seen, first_task_id, latest_task_id, latest_role, reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(atom_id, other_atom_id) DO UPDATE SET
                    last_seen=excluded.last_seen, latest_task_id=excluded.latest_task_id,
                    latest_role=excluded.latest_role, reason=excluded.reason
            """, (a, b, now, now, task_id, task_id, role or "unknown", item["reason"]))
            count += 1
        self.db.commit()
        return count

    def contradiction_stats(self):
        try:
            row = self.db.execute("SELECT COUNT(*) FROM evidence_contradictions").fetchone()
        except Exception:
            return {"contradictions": 0}
        return {"contradictions": row[0]}

    def stats(self):
        row = self.db.execute(
            "SELECT COUNT(*), COALESCE(SUM(confirmation_count), 0) "
            "FROM evidence_ledger"
        ).fetchone()
        return {"atoms": row[0], "confirmations": row[1]}
