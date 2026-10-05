import base64
import hashlib
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone


class RecoveryTrustError(ValueError):
    pass


class RecoveryAttestorStatus:
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


_ALLOWED_TRANSITIONS = {
    RecoveryAttestorStatus.ACTIVE: {
        RecoveryAttestorStatus.SUSPENDED,
        RecoveryAttestorStatus.REVOKED,
    },
    RecoveryAttestorStatus.SUSPENDED: {
        RecoveryAttestorStatus.ACTIVE,
        RecoveryAttestorStatus.REVOKED,
    },
    RecoveryAttestorStatus.REVOKED: set(),
}


@dataclass(frozen=True)
class RecoveryAttestor:
    key_id: str
    public_key: str
    name: str
    enabled: bool = True


class RecoveryAttestorStore:
    """Durable SQLite state for recovery attestor trust and lifecycle."""

    SCHEMA_VERSION = "recovery-attestor-store-v1"

    def __init__(self, db):
        self.db = db
        self._init_schema()

    def _connect(self):
        if isinstance(self.db, sqlite3.Connection):
            return self.db, False
        return sqlite3.connect(self.db, timeout=30.0), True

    def _init_schema(self):
        conn, owned = self._connect()
        try:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS recovery_attestors (
                    key_id TEXT PRIMARY KEY,
                    public_key TEXT NOT NULL,
                    name TEXT NOT NULL,
                    enabled INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    schema_version TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS recovery_attestor_history (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_id TEXT NOT NULL,
                    from_status TEXT,
                    to_status TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    schema_version TEXT NOT NULL,
                    FOREIGN KEY(key_id) REFERENCES recovery_attestors(key_id)
                );
                CREATE INDEX IF NOT EXISTS idx_recovery_attestor_history_key
                    ON recovery_attestor_history(key_id, event_id);
                """
            )
            if owned:
                conn.commit()
        finally:
            if owned:
                conn.close()

    def load(self):
        conn, owned = self._connect()
        try:
            return conn.execute(
                "SELECT key_id, public_key, name, enabled, status "
                "FROM recovery_attestors ORDER BY key_id"
            ).fetchall()
        finally:
            if owned:
                conn.close()

    def history(self, key_id):
        conn, owned = self._connect()
        try:
            return conn.execute(
                "SELECT from_status, to_status, occurred_at, reason "
                "FROM recovery_attestor_history WHERE key_id = ? ORDER BY event_id",
                (key_id,),
            ).fetchall()
        finally:
            if owned:
                conn.close()

    def insert(self, attestor, status, occurred_at):
        conn, owned = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO recovery_attestors "
                "(key_id, public_key, name, enabled, status, schema_version) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (attestor.key_id, attestor.public_key, attestor.name, int(attestor.enabled), status, self.SCHEMA_VERSION),
            )
            conn.execute(
                "INSERT INTO recovery_attestor_history "
                "(key_id, from_status, to_status, occurred_at, reason, schema_version) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (attestor.key_id, None, status, occurred_at, "registered", self.SCHEMA_VERSION),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            if owned:
                conn.close()

    def transition(self, key_id, expected_status, new_status, reason, occurred_at):
        conn, owned = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT status FROM recovery_attestors WHERE key_id = ?", (key_id,)
            ).fetchone()
            if row is None:
                raise RecoveryTrustError("untrusted_attestor")
            if row[0] != expected_status:
                raise RecoveryTrustError("attestor_state_changed")
            conn.execute(
                "UPDATE recovery_attestors SET status = ? WHERE key_id = ? AND status = ?",
                (new_status, key_id, expected_status),
            )
            conn.execute(
                "INSERT INTO recovery_attestor_history "
                "(key_id, from_status, to_status, occurred_at, reason, schema_version) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (key_id, expected_status, new_status, occurred_at, reason, self.SCHEMA_VERSION),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            if owned:
                conn.close()


class RecoveryAttestorRegistry:
    """Explicit trust anchors and auditable lifecycle for recovery attestors."""

    def __init__(self, attestors=None, store=None):
        self._attestors = {}
        self._status = {}
        self._history = {}
        self._store = store
        if store is not None and not isinstance(store, RecoveryAttestorStore):
            store = RecoveryAttestorStore(store)
            self._store = store
        if self._store is not None:
            self._load_store()
        for attestor in attestors or ():
            self.register(attestor)

    def _load_store(self):
        for key_id, public_key, name, enabled, status in self._store.load():
            self._attestors[key_id] = RecoveryAttestor(
                key_id=key_id, public_key=public_key, name=name, enabled=bool(enabled)
            )
            self._status[key_id] = status
            self._history[key_id] = [
                {
                    "from_status": from_status,
                    "to_status": to_status,
                    "occurred_at": occurred_at,
                    "reason": reason,
                }
                for from_status, to_status, occurred_at, reason in self._store.history(key_id)
            ]

    def register(self, attestor):
        if not isinstance(attestor, RecoveryAttestor):
            raise RecoveryTrustError("attestor_required")
        try:
            raw = base64.urlsafe_b64decode(attestor.public_key.encode("ascii"))
        except Exception as exc:
            raise RecoveryTrustError("invalid_attestor_public_key") from exc
        if len(raw) != 32:
            raise RecoveryTrustError("invalid_attestor_public_key")
        expected = "ed25519-" + hashlib.sha256(raw).hexdigest()[:16]
        if attestor.key_id != expected:
            raise RecoveryTrustError("attestor_key_id_mismatch")
        if not attestor.name.strip():
            raise RecoveryTrustError("attestor_name_required")
        if attestor.key_id in self._attestors:
            existing = self._attestors[attestor.key_id]
            if existing.public_key != attestor.public_key:
                raise RecoveryTrustError("attestor_key_mismatch")
            return
        self._attestors[attestor.key_id] = attestor
        status = (
            RecoveryAttestorStatus.ACTIVE
            if attestor.enabled
            else RecoveryAttestorStatus.SUSPENDED
        )
        self._status[attestor.key_id] = status
        occurred_at = datetime.now(timezone.utc).isoformat()
        self._history[attestor.key_id] = [
            {
                "from_status": None,
                "to_status": status,
                "occurred_at": occurred_at,
                "reason": "registered",
            }
        ]
        if self._store is not None:
            try:
                self._store.insert(attestor, status, self._history[attestor.key_id][0]["occurred_at"])
            except Exception:
                self._attestors.pop(attestor.key_id, None)
                self._status.pop(attestor.key_id, None)
                self._history.pop(attestor.key_id, None)
                raise

    def get(self, key_id):
        return self._attestors.get(key_id)

    def status(self, key_id):
        if key_id not in self._attestors:
            raise RecoveryTrustError("untrusted_attestor")
        return self._status[key_id]

    def transition(self, key_id, new_status, reason):
        if key_id not in self._attestors:
            raise RecoveryTrustError("untrusted_attestor")
        if new_status not in _ALLOWED_TRANSITIONS:
            raise RecoveryTrustError("invalid_attestor_status")
        current = self._status[key_id]
        if new_status not in _ALLOWED_TRANSITIONS[current]:
            raise RecoveryTrustError("invalid_attestor_transition")
        if not isinstance(reason, str) or not reason.strip():
            raise RecoveryTrustError("attestor_transition_reason_required")
        occurred_at = datetime.now(timezone.utc).isoformat()
        if self._store is not None:
            self._store.transition(key_id, current, new_status, reason.strip(), occurred_at)
        self._status[key_id] = new_status
        self._history[key_id].append(
            {
                "from_status": current,
                "to_status": new_status,
                "occurred_at": datetime.now(timezone.utc).isoformat(),
                "reason": reason.strip(),
            }
        )
        return new_status

    def history(self, key_id):
        if key_id not in self._attestors:
            raise RecoveryTrustError("untrusted_attestor")
        return [dict(event) for event in self._history[key_id]]

    def require(self, key_id, public_key):
        attestor = self.get(key_id)
        if attestor is None:
            raise RecoveryTrustError("untrusted_attestor")
        if not attestor.enabled:
            raise RecoveryTrustError("attestor_disabled")
        if self._status[key_id] == RecoveryAttestorStatus.SUSPENDED:
            raise RecoveryTrustError("attestor_suspended")
        if self._status[key_id] == RecoveryAttestorStatus.REVOKED:
            raise RecoveryTrustError("attestor_revoked")
        if attestor.public_key != public_key:
            raise RecoveryTrustError("attestor_key_mismatch")
        return attestor

    def to_dict(self):
        return {
            key_id: {
                "key_id": attestor.key_id,
                "public_key": attestor.public_key,
                "name": attestor.name,
                "enabled": attestor.enabled,
                "status": self._status[key_id],
                "history": self.history(key_id),
            }
            for key_id, attestor in sorted(self._attestors.items())
        }
