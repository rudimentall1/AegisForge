import json
from datetime import datetime, timezone


class CapabilityGrantStoreError(ValueError):
    pass


class CapabilityGrantStore:
    """Persistent lifecycle registry for signed capability grants.

    A grant can be ACTIVE, CONSUMED, or REVOKED. The registry is separate
    from the signed artifact: the signature proves what was authorized, while
    this store proves whether that authorization is still usable.
    """

    TABLE = "capability_grants"

    def __init__(self, db):
        if db is None:
            raise CapabilityGrantStoreError("database_required")
        self.db = db
        self.db.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {self.TABLE} (
                grant_id TEXT PRIMARY KEY,
                nonce TEXT NOT NULL UNIQUE,
                task_id TEXT NOT NULL,
                key_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                consumed_at TEXT,
                revoked_at TEXT,
                revoke_reason TEXT
            )
            """
        )
        self.db.commit()

    def register(self, signed_grant):
        grant = signed_grant.grant
        now = datetime.now(timezone.utc).isoformat()
        payload = json.dumps(
            signed_grant.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        )
        try:
            self.db.execute(
                f"""
                INSERT INTO {self.TABLE}
                (grant_id, nonce, task_id, key_id, payload, issued_at,
                 expires_at, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?)
                """,
                (
                    grant.grant_id,
                    grant.nonce,
                    grant.task_id,
                    signed_grant.key_id,
                    payload,
                    grant.issued_at,
                    grant.expires_at,
                    now,
                ),
            )
            self.db.commit()
        except Exception as exc:
            self.db.rollback()
            if "UNIQUE" not in str(exc).upper():
                raise
            row = self.db.execute(
                f"SELECT status FROM {self.TABLE} WHERE grant_id=?",
                (grant.grant_id,),
            ).fetchone()
            if row and row[0] == "ACTIVE":
                return False
            raise CapabilityGrantStoreError("grant_already_finalized") from exc
        return True

    def ensure_registered(self, signed_grant):
        row = self.db.execute(
            f"SELECT status FROM {self.TABLE} WHERE grant_id=?",
            (signed_grant.grant.grant_id,),
        ).fetchone()
        if row:
            return row[0]
        self.register(signed_grant)
        return "ACTIVE"

    def status(self, grant_id):
        row = self.db.execute(
            f"SELECT status FROM {self.TABLE} WHERE grant_id=?",
            (str(grant_id),),
        ).fetchone()
        return row[0] if row else None

    def revoke(self, grant_id, reason="revoked_by_governance"):
        now = datetime.now(timezone.utc).isoformat()
        cursor = self.db.execute(
            f"""
            UPDATE {self.TABLE}
            SET status='REVOKED', revoked_at=?, revoke_reason=?
            WHERE grant_id=? AND status='ACTIVE'
            """,
            (now, str(reason)[:500], str(grant_id)),
        )
        self.db.commit()
        if cursor.rowcount != 1:
            status = self.status(grant_id)
            if status is None:
                raise CapabilityGrantStoreError("grant_not_found")
            raise CapabilityGrantStoreError("grant_not_active")
        return True

    def consume(self, grant_id, receipt_id, consumed_at):
        cursor = self.db.execute(
            f"""
            UPDATE {self.TABLE}
            SET status='CONSUMED', consumed_at=?
            WHERE grant_id=? AND status='ACTIVE'
            """,
            (consumed_at, str(grant_id)),
        )
        self.db.commit()
        if cursor.rowcount != 1:
            status = self.status(grant_id)
            if status == "REVOKED":
                raise CapabilityGrantStoreError("grant_revoked")
            if status == "CONSUMED":
                raise CapabilityGrantStoreError("grant_replayed")
            raise CapabilityGrantStoreError("grant_not_found")
        return True
