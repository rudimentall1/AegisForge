import sqlite3
from dataclasses import dataclass


SCHEMA_VERSION = "executor-identity-registry-v1"


class ExecutorIdentityRegistryError(ValueError):
    pass


@dataclass(frozen=True)
class ExecutorIdentityRecord:
    executor_id: str
    version: str
    implementation_digest: str
    status: str = "ACTIVE"
    registry_epoch: int = 1

    def to_dict(self):
        return {
            "schema_version": SCHEMA_VERSION,
            "executor_id": self.executor_id,
            "version": self.version,
            "implementation_digest": self.implementation_digest,
            "status": self.status,
            "registry_epoch": self.registry_epoch,
        }


class ExecutorIdentityRegistry:
    """Persistent trust anchor for executor implementation identity.

    An executor identity is immutable for a given (executor_id, version).
    Process restarts must not permit silent replacement of its implementation.
    """

    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"

    def __init__(self, db):
        if not isinstance(db, sqlite3.Connection):
            raise ExecutorIdentityRegistryError("sqlite_connection_required")
        self.db = db
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS executor_identity_registry (
                executor_id TEXT NOT NULL,
                version TEXT NOT NULL,
                implementation_digest TEXT NOT NULL,
                status TEXT NOT NULL,
                registry_epoch INTEGER NOT NULL,
                schema_version TEXT NOT NULL,
                PRIMARY KEY (executor_id, version)
            )"""
        )
        self.db.commit()

    def register(self, executor_id, version, implementation_digest):
        if not executor_id or not isinstance(executor_id, str):
            raise ExecutorIdentityRegistryError("executor_id_required")
        if not version or not isinstance(version, str):
            raise ExecutorIdentityRegistryError("executor_version_required")
        if not implementation_digest or not isinstance(implementation_digest, str):
            raise ExecutorIdentityRegistryError("executor_implementation_digest_required")

        row = self.db.execute(
            "SELECT implementation_digest,status,registry_epoch FROM executor_identity_registry "
            "WHERE executor_id = ? AND version = ?",
            (executor_id, version),
        ).fetchone()
        if row is not None:
            existing_digest, status, epoch = row
            if existing_digest != implementation_digest:
                raise ExecutorIdentityRegistryError("executor_identity_conflict")
            if status != self.ACTIVE:
                raise ExecutorIdentityRegistryError("executor_identity_not_active")
            return ExecutorIdentityRecord(executor_id, version, existing_digest, status, int(epoch))

        next_epoch = self._next_epoch()
        self.db.execute(
            """INSERT INTO executor_identity_registry
               (executor_id,version,implementation_digest,status,registry_epoch,schema_version)
               VALUES(?,?,?,?,?,?)""",
            (executor_id, version, implementation_digest, self.ACTIVE, next_epoch, SCHEMA_VERSION),
        )
        self.db.commit()
        return ExecutorIdentityRecord(executor_id, version, implementation_digest, self.ACTIVE, next_epoch)

    def get(self, executor_id, version):
        row = self.db.execute(
            "SELECT implementation_digest,status,registry_epoch FROM executor_identity_registry "
            "WHERE executor_id = ? AND version = ?",
            (executor_id, version),
        ).fetchone()
        if row is None:
            return None
        return ExecutorIdentityRecord(executor_id, version, row[0], row[1], int(row[2]))

    def set_status(self, executor_id, version, status):
        if status not in {self.ACTIVE, self.SUSPENDED, self.REVOKED}:
            raise ExecutorIdentityRegistryError("invalid_executor_identity_status")
        record = self.get(executor_id, version)
        if record is None:
            raise ExecutorIdentityRegistryError("executor_identity_not_registered")
        epoch = self._next_epoch()
        self.db.execute(
            "UPDATE executor_identity_registry SET status = ?, registry_epoch = ? "
            "WHERE executor_id = ? AND version = ?",
            (status, epoch, executor_id, version),
        )
        self.db.commit()
        return ExecutorIdentityRecord(executor_id, version, record.implementation_digest, status, epoch)

    def _next_epoch(self):
        row = self.db.execute("SELECT MAX(registry_epoch) FROM executor_identity_registry").fetchone()
        return int(row[0] or 0) + 1
