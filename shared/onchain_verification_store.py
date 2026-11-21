"""Append-only persistence for compiler-backed on-chain verification evidence."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
from typing import Any

from shared.onchain_target_store import OnchainTargetRecord, OnchainTargetStore


_ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
_HASH32_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_RE = re.compile(r"^ghcr\.io/foundry-rs/foundry@sha256:[0-9a-f]{64}$")
_ALLOWED_STATUSES = {"VERIFIED", "MISMATCH", "INCOMPLETE"}


class OnchainVerificationError(ValueError):
    """Invalid or unbound compiler verification evidence."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _validate_digest(name: str, value: object, *, required: bool) -> str:
    if not isinstance(value, str):
        raise OnchainVerificationError(f"{name}_invalid")
    if not value and not required:
        return ""
    if not _HASH32_RE.fullmatch(value):
        raise OnchainVerificationError(f"{name}_invalid")
    return value


@dataclass(frozen=True, slots=True)
class OnchainVerificationRecord:
    target_id: str
    chain_id: int
    address: str
    block_number: int
    block_hash: str
    source_sha256: str
    standard_json_input_sha256: str
    compiler_version: str
    compiler_binary_sha256: str
    compiled_runtime_sha256: str
    deployed_runtime_sha256: str
    status: str
    reason: str
    compiler_image: str = ""
    isolation: str = ""
    verification_id: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.target_id, str) or not _HASH32_RE.fullmatch(self.target_id):
            raise OnchainVerificationError("verification_target_id_invalid")
        if (
            not isinstance(self.chain_id, int)
            or isinstance(self.chain_id, bool)
            or self.chain_id <= 0
        ):
            raise OnchainVerificationError("verification_chain_id_invalid")
        if not isinstance(self.address, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", self.address):
            raise OnchainVerificationError("verification_address_invalid")
        object.__setattr__(self, "address", self.address.lower())
        if (
            not isinstance(self.block_number, int)
            or isinstance(self.block_number, bool)
            or self.block_number < 0
        ):
            raise OnchainVerificationError("verification_block_number_invalid")
        if not isinstance(self.block_hash, str) or not re.fullmatch(r"(?:0x)?[0-9a-fA-F]{64}", self.block_hash):
            raise OnchainVerificationError("verification_block_hash_invalid")
        block_hash = self.block_hash.lower()
        object.__setattr__(self, "block_hash", block_hash if block_hash.startswith("0x") else "0x" + block_hash)

        for name, required in (
            ("source_sha256", True),
            ("standard_json_input_sha256", False),
            ("compiler_binary_sha256", False),
            ("compiled_runtime_sha256", False),
            ("deployed_runtime_sha256", True),
        ):
            value = _validate_digest(name, getattr(self, name), required=required)
            object.__setattr__(self, name, value)

        for name in ("compiler_version", "reason", "compiler_image", "isolation"):
            value = getattr(self, name)
            if not isinstance(value, str) or (name == "reason" and not value.strip()):
                raise OnchainVerificationError(f"verification_{name}_invalid")

        if self.status not in _ALLOWED_STATUSES:
            raise OnchainVerificationError("verification_status_invalid")
        if self.compiler_image and not _IMAGE_RE.fullmatch(self.compiler_image):
            raise OnchainVerificationError("verification_compiler_image_invalid")
        if self.isolation and self.isolation != "container":
            raise OnchainVerificationError("verification_isolation_invalid")

        if self.status in {"VERIFIED", "MISMATCH"}:
            if not all((
                self.standard_json_input_sha256,
                self.compiler_version,
                self.compiler_binary_sha256,
                self.compiled_runtime_sha256,
                self.deployed_runtime_sha256,
                self.compiler_image,
                self.isolation,
            )):
                raise OnchainVerificationError("verified_compiler_evidence_incomplete")
            if self.status == "VERIFIED":
                if self.compiled_runtime_sha256 != self.deployed_runtime_sha256:
                    raise OnchainVerificationError("verified_runtime_digests_mismatch")
                if self.reason != "runtime_bytecode_exact_match":
                    raise OnchainVerificationError("verified_reason_invalid")
            else:
                if self.compiled_runtime_sha256 == self.deployed_runtime_sha256:
                    raise OnchainVerificationError("mismatch_runtime_digests_equal")
                if self.reason != "runtime_bytecode_mismatch":
                    raise OnchainVerificationError("mismatch_reason_invalid")

        identity = {
            "target_id": self.target_id,
            "chain_id": self.chain_id,
            "address": self.address,
            "block_number": self.block_number,
            "block_hash": self.block_hash,
            "source_sha256": self.source_sha256,
            "standard_json_input_sha256": self.standard_json_input_sha256,
            "compiler_version": self.compiler_version,
            "compiler_binary_sha256": self.compiler_binary_sha256,
            "compiled_runtime_sha256": self.compiled_runtime_sha256,
            "deployed_runtime_sha256": self.deployed_runtime_sha256,
            "status": self.status,
            "reason": self.reason,
            "compiler_image": self.compiler_image,
            "isolation": self.isolation,
        }
        object.__setattr__(
            self,
            "verification_id",
            hashlib.sha256(_canonical_json(identity).encode("utf-8")).hexdigest(),
        )

    @classmethod
    def from_target(
        cls,
        target: OnchainTargetRecord,
        *,
        status: str,
        reason: str,
        compiler_version: str = "",
        compiler_binary_sha256: str = "",
        compiled_runtime_sha256: str = "",
        compiler_image: str = "",
        isolation: str = "",
    ) -> "OnchainVerificationRecord":
        if not isinstance(target, OnchainTargetRecord):
            raise OnchainVerificationError("onchain_target_record_required")
        return cls(
            target_id=target.target_id,
            chain_id=target.chain_id,
            address=target.address,
            block_number=target.block_number,
            block_hash=target.block_hash,
            source_sha256=target.source_sha256,
            standard_json_input_sha256=target.standard_json_input_sha256,
            compiler_version=compiler_version,
            compiler_binary_sha256=compiler_binary_sha256,
            compiled_runtime_sha256=compiled_runtime_sha256,
            deployed_runtime_sha256=target.runtime_code_sha256,
            status=status,
            reason=reason,
            compiler_image=compiler_image,
            isolation=isolation,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "chain_id": self.chain_id,
            "address": self.address,
            "block_number": self.block_number,
            "block_hash": self.block_hash,
            "source_sha256": self.source_sha256,
            "standard_json_input_sha256": self.standard_json_input_sha256,
            "compiler_version": self.compiler_version,
            "compiler_binary_sha256": self.compiler_binary_sha256,
            "compiled_runtime_sha256": self.compiled_runtime_sha256,
            "deployed_runtime_sha256": self.deployed_runtime_sha256,
            "status": self.status,
            "reason": self.reason,
            "compiler_image": self.compiler_image,
            "isolation": self.isolation,
        }


class OnchainVerificationStore:
    """Append-only verification ledger bound to persisted OnchainTargetRecord rows."""

    def __init__(self, target_store: OnchainTargetStore):
        if not isinstance(target_store, OnchainTargetStore):
            raise OnchainVerificationError("onchain_target_store_required")
        self.target_store = target_store
        self.db = target_store.db
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS onchain_verifications (
                verification_id TEXT PRIMARY KEY,
                target_id TEXT NOT NULL,
                chain_id INTEGER NOT NULL,
                address TEXT NOT NULL,
                block_number INTEGER NOT NULL,
                block_hash TEXT NOT NULL,
                source_sha256 TEXT NOT NULL,
                standard_json_input_sha256 TEXT NOT NULL,
                compiler_version TEXT NOT NULL,
                compiler_binary_sha256 TEXT NOT NULL,
                compiled_runtime_sha256 TEXT NOT NULL,
                deployed_runtime_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                reason TEXT NOT NULL,
                compiler_image TEXT NOT NULL,
                isolation TEXT NOT NULL,
                record_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        self.db.execute("""
            CREATE INDEX IF NOT EXISTS idx_onchain_verifications_target
            ON onchain_verifications(target_id, created_at, verification_id)
        """)
        self.db.execute("""
            CREATE TRIGGER IF NOT EXISTS onchain_verifications_no_update
            BEFORE UPDATE ON onchain_verifications
            BEGIN
                SELECT RAISE(ABORT, 'onchain_verification_immutable');
            END
        """)
        self.db.execute("""
            CREATE TRIGGER IF NOT EXISTS onchain_verifications_no_delete
            BEFORE DELETE ON onchain_verifications
            BEGIN
                SELECT RAISE(ABORT, 'onchain_verification_immutable');
            END
        """)
        self.db.commit()

    def put(self, record: OnchainVerificationRecord) -> str:
        if not isinstance(record, OnchainVerificationRecord):
            raise OnchainVerificationError("onchain_verification_record_required")
        target = self.target_store.get(record.target_id)
        if target is None:
            raise OnchainVerificationError("verification_target_missing")
        expected = (
            target.chain_id,
            target.address,
            target.block_number,
            target.block_hash,
            target.source_sha256,
            target.standard_json_input_sha256,
            target.runtime_code_sha256,
        )
        actual = (
            record.chain_id,
            record.address,
            record.block_number,
            record.block_hash,
            record.source_sha256,
            record.standard_json_input_sha256,
            record.deployed_runtime_sha256,
        )
        if actual != expected:
            raise OnchainVerificationError("verification_target_binding_mismatch")

        payload = record.to_dict()
        record_json = _canonical_json(payload)
        with self.db:
            existing = self.db.execute(
                "SELECT record_json FROM onchain_verifications WHERE verification_id = ?",
                (record.verification_id,),
            ).fetchone()
            if existing is not None:
                if existing[0] != record_json:
                    raise OnchainVerificationError("verification_id_conflict")
                return record.verification_id
            self.db.execute(
                """
                INSERT INTO onchain_verifications (
                    verification_id, target_id, chain_id, address, block_number,
                    block_hash, source_sha256, standard_json_input_sha256,
                    compiler_version, compiler_binary_sha256, compiled_runtime_sha256,
                    deployed_runtime_sha256, status, reason, compiler_image,
                    isolation, record_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.verification_id,
                    record.target_id,
                    record.chain_id,
                    record.address,
                    record.block_number,
                    record.block_hash,
                    record.source_sha256,
                    record.standard_json_input_sha256,
                    record.compiler_version,
                    record.compiler_binary_sha256,
                    record.compiled_runtime_sha256,
                    record.deployed_runtime_sha256,
                    record.status,
                    record.reason,
                    record.compiler_image,
                    record.isolation,
                    record_json,
                ),
            )
        return record.verification_id

    def verify_and_persist(
        self,
        target_id: str,
        contract_file: str,
        *,
        image: str | None = None,
    ) -> OnchainVerificationRecord:
        """Run the production compiler verifier and append its result to the ledger."""
        target = self.target_store.get(target_id)
        if target is None:
            raise OnchainVerificationError("verification_target_missing")
        from shared.solidity_compiler import verify_onchain_target

        result = verify_onchain_target(target, contract_file, image=image)
        record = OnchainVerificationRecord.from_target(
            target,
            status=result.status,
            reason=result.reason,
            compiler_version=result.compiler_version,
            compiler_binary_sha256=result.compiler_binary_sha256,
            compiled_runtime_sha256=result.compiled_runtime_sha256,
            compiler_image=result.compiler_image,
            isolation=result.isolation,
        )
        verification_id = self.put(record)
        persisted = self.get(verification_id)
        if persisted is None:
            raise OnchainVerificationError("verification_persistence_failed")
        return persisted

    @staticmethod
    def _from_json(record_json: str) -> OnchainVerificationRecord:
        payload = json.loads(record_json)
        return OnchainVerificationRecord(**payload)

    def get(self, verification_id: str) -> OnchainVerificationRecord | None:
        if not isinstance(verification_id, str) or not _HASH32_RE.fullmatch(verification_id):
            return None
        row = self.db.execute(
            "SELECT record_json FROM onchain_verifications WHERE verification_id = ?",
            (verification_id,),
        ).fetchone()
        if row is None:
            return None
        record = self._from_json(row[0])
        if record.verification_id != verification_id:
            raise OnchainVerificationError("verification_record_digest_mismatch")
        return record

    def list_for_target(self, target_id: str) -> list[OnchainVerificationRecord]:
        if not isinstance(target_id, str) or not _HASH32_RE.fullmatch(target_id):
            return []
        rows = self.db.execute(
            """
            SELECT record_json FROM onchain_verifications
            WHERE target_id = ?
            ORDER BY created_at, verification_id
            """,
            (target_id,),
        ).fetchall()
        return [self._from_json(row[0]) for row in rows]

    def count(self) -> int:
        return int(self.db.execute("SELECT COUNT(*) FROM onchain_verifications").fetchone()[0])
