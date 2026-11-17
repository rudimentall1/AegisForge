import hashlib
import json
import sqlite3
from datetime import datetime, timezone


SCHEMA_VERSION = "recovery-evidence-v1"
GENESIS_HASH = "0" * 64


class RecoveryEvidenceError(ValueError):
    pass


class RecoveryEvidenceChain:
    """Tamper-evident, append-only recovery evidence chain.

    The chain is scoped per recovery_id. Each event commits the previous
    event hash, so a verifier can detect deletion, reordering, or mutation.
    This is an integrity artifact, not a trust claim: the chain is not signed
    by an external authority.
    """

    TABLE = "recovery_evidence_events"

    def __init__(self, db):
        if db is None:
            raise RecoveryEvidenceError("database_required")
        self.db = db
        self.db.execute(f"""
            CREATE TABLE IF NOT EXISTS {self.TABLE} (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                recovery_id TEXT NOT NULL,
                attempt_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL UNIQUE
            )
        """)
        self.db.execute(
            f"CREATE INDEX IF NOT EXISTS idx_{self.TABLE}_recovery "
            f"ON {self.TABLE}(recovery_id, event_id)"
        )
        self.db.commit()

    @staticmethod
    def _now(now=None):
        return now or datetime.now(timezone.utc)

    @staticmethod
    def _canonical(value):
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    @classmethod
    def _hash_event(cls, recovery_id, attempt_id, event_type, payload,
                    occurred_at, prev_hash):
        body = cls._canonical({
            "schema_version": SCHEMA_VERSION,
            "recovery_id": str(recovery_id),
            "attempt_id": str(attempt_id),
            "event_type": str(event_type),
            "payload": payload,
            "occurred_at": str(occurred_at),
            "prev_hash": str(prev_hash),
        })
        return hashlib.sha256(body.encode("utf-8")).hexdigest()

    def append(self, recovery_id, attempt_id, event_type, payload=None, now=None):
        if not str(recovery_id).strip():
            raise RecoveryEvidenceError("recovery_id_required")
        if not str(attempt_id).strip():
            raise RecoveryEvidenceError("attempt_id_required")
        if not str(event_type).strip():
            raise RecoveryEvidenceError("event_type_required")
        if payload is None:
            payload = {}
        if not isinstance(payload, dict):
            raise RecoveryEvidenceError("payload_must_be_dict")

        occurred_at = self._now(now).isoformat()
        row = self.db.execute(
            f"SELECT event_hash FROM {self.TABLE} "
            "WHERE recovery_id=? ORDER BY event_id DESC LIMIT 1",
            (str(recovery_id),),
        ).fetchone()
        prev_hash = row[0] if row else GENESIS_HASH
        event_hash = self._hash_event(
            recovery_id, attempt_id, event_type, payload, occurred_at, prev_hash
        )
        try:
            self.db.execute(
                f"""INSERT INTO {self.TABLE}
                    (recovery_id, attempt_id, event_type, payload,
                     occurred_at, prev_hash, event_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(recovery_id),
                    str(attempt_id),
                    str(event_type),
                    self._canonical(payload),
                    occurred_at,
                    prev_hash,
                    event_hash,
                ),
            )
            self.db.commit()
        except sqlite3.IntegrityError as exc:
            self.db.rollback()
            raise RecoveryEvidenceError("evidence_append_conflict") from exc
        return self.get_event(event_hash)

    def get_event(self, event_hash):
        row = self.db.execute(
            f"""SELECT event_id,recovery_id,attempt_id,event_type,payload,
                       occurred_at,prev_hash,event_hash
                FROM {self.TABLE} WHERE event_hash=?""",
            (str(event_hash),),
        ).fetchone()
        if row is None:
            raise RecoveryEvidenceError("evidence_event_not_found")
        return self._row_to_dict(row)

    def events(self, recovery_id):
        rows = self.db.execute(
            f"""SELECT event_id,recovery_id,attempt_id,event_type,payload,
                       occurred_at,prev_hash,event_hash
                FROM {self.TABLE}
                WHERE recovery_id=? ORDER BY event_id ASC""",
            (str(recovery_id),),
        ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def export_artifact(self, recovery_id):
        """Return a portable JSON-compatible recovery evidence artifact."""
        events = self.events(recovery_id)
        result = self.verify(recovery_id)
        if not result["valid"]:
            raise RecoveryEvidenceError("cannot_export_invalid_chain")
        attempt_ids = {event["attempt_id"] for event in events}
        recovery_ids = {event["recovery_id"] for event in events}
        if len(recovery_ids) != 1 or (events and len(attempt_ids) != 1):
            raise RecoveryEvidenceError("inconsistent_recovery_chain")
        return {
            "schema_version": SCHEMA_VERSION,
            "recovery_id": str(recovery_id),
            "attempt_id": events[0]["attempt_id"] if events else None,
            "events": events,
            "head_hash": result["head_hash"],
        }

    @classmethod
    def verify_artifact(cls, artifact):
        """Verify a portable artifact without a database or chain instance."""
        if not isinstance(artifact, dict):
            return {"valid": False, "error": "artifact_must_be_dict"}
        if artifact.get("schema_version") != SCHEMA_VERSION:
            return {"valid": False, "error": "unsupported_schema_version"}
        recovery_id = artifact.get("recovery_id")
        events = artifact.get("events")
        if not isinstance(recovery_id, str) or not recovery_id.strip():
            return {"valid": False, "error": "recovery_id_required"}
        if not isinstance(events, list):
            return {"valid": False, "error": "events_must_be_list"}
        expected_prev = GENESIS_HASH
        attempt_id = artifact.get("attempt_id")
        for event in events:
            if not isinstance(event, dict):
                return {"valid": False, "error": "event_must_be_dict"}
            if event.get("recovery_id") != recovery_id:
                return {"valid": False, "error": "recovery_id_mismatch"}
            if attempt_id is not None and event.get("attempt_id") != attempt_id:
                return {"valid": False, "error": "attempt_id_mismatch"}
            if event.get("prev_hash") != expected_prev:
                return {
                    "valid": False,
                    "events": len(events),
                    "error": "broken_prev_hash",
                    "event_hash": event.get("event_hash"),
                }
            required = ("attempt_id", "event_type", "payload", "occurred_at", "prev_hash", "event_hash")
            if any(field not in event for field in required):
                return {"valid": False, "error": "event_field_missing"}
            expected_hash = cls._hash_event(
                event["recovery_id"],
                event["attempt_id"],
                event["event_type"],
                event["payload"],
                event["occurred_at"],
                event["prev_hash"],
            )
            if event["event_hash"] != expected_hash:
                return {
                    "valid": False,
                    "events": len(events),
                    "error": "event_hash_mismatch",
                    "event_hash": event["event_hash"],
                }
            expected_prev = event["event_hash"]
        if artifact.get("head_hash") != expected_prev:
            return {
                "valid": False,
                "events": len(events),
                "error": "head_hash_mismatch",
            }
        return {"valid": True, "events": len(events), "head_hash": expected_prev}

    def verify(self, recovery_id):
        events = self.events(recovery_id)
        expected_prev = GENESIS_HASH
        for event in events:
            if event["prev_hash"] != expected_prev:
                return {
                    "valid": False,
                    "events": len(events),
                    "error": "broken_prev_hash",
                    "event_hash": event["event_hash"],
                }
            expected_hash = self._hash_event(
                event["recovery_id"],
                event["attempt_id"],
                event["event_type"],
                event["payload"],
                event["occurred_at"],
                event["prev_hash"],
            )
            if event["event_hash"] != expected_hash:
                return {
                    "valid": False,
                    "events": len(events),
                    "error": "event_hash_mismatch",
                    "event_hash": event["event_hash"],
                }
            expected_prev = event["event_hash"]
        return {
            "valid": True,
            "events": len(events),
            "head_hash": expected_prev if events else GENESIS_HASH,
        }

    @staticmethod
    def _row_to_dict(row):
        return {
            "event_id": row[0],
            "recovery_id": row[1],
            "attempt_id": row[2],
            "event_type": row[3],
            "payload": json.loads(row[4]),
            "occurred_at": row[5],
            "prev_hash": row[6],
            "event_hash": row[7],
        }
