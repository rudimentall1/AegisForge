"""Immutable persistence for source-backed EVM contract targets.

This store is intentionally separate from ResearchCase and queue payloads:
ResearchCase currently models pinned Git repositories, while an on-chain target
is identified by chain/address/block and independently acquired source bytes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
import sqlite3
from typing import Any


_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HASH32_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{64}$")
_MAX_SOURCE_BYTES = 4 * 1024 * 1024
_MAX_SOURCE_FILES = 500


class OnchainTargetError(ValueError):
    """Raised when an on-chain target is malformed or conflicts with stored state."""


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _validate_source_files(source_files: dict[str, str]) -> dict[str, str]:
    if not isinstance(source_files, dict) or not source_files:
        raise OnchainTargetError("source_files_required")
    if len(source_files) > _MAX_SOURCE_FILES:
        raise OnchainTargetError("source_file_count_exceeded")

    normalized = {}
    total_bytes = 0
    for path, content in source_files.items():
        if (
            not isinstance(path, str)
            or not path
            or path.startswith("/")
            or "\\" in path
            or "\x00" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
        ):
            raise OnchainTargetError("source_path_invalid")
        if not isinstance(content, str) or not content:
            raise OnchainTargetError("source_content_invalid")
        try:
            encoded = content.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise OnchainTargetError("source_content_invalid") from exc
        total_bytes += len(encoded)
        if total_bytes > _MAX_SOURCE_BYTES:
            raise OnchainTargetError("source_bundle_too_large")
        normalized[path] = content
    return dict(sorted(normalized.items()))


@dataclass(frozen=True, slots=True)
class OnchainTargetRecord:
    chain_id: int
    address: str
    block_number: int
    block_hash: str
    runtime_code_sha256: str
    source_files: dict[str, str]
    source_provider: str
    compiler_version: str = ""
    contract_name: str = ""
    proxy_type: str | None = None
    implementations: tuple[str, ...] = ()
    source_sha256: str = ""
    target_id: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.chain_id, int)
            or isinstance(self.chain_id, bool)
            or self.chain_id <= 0
        ):
            raise OnchainTargetError("chain_id_invalid")
        if not isinstance(self.address, str) or not _ADDRESS_RE.fullmatch(self.address):
            raise OnchainTargetError("contract_address_invalid")
        object.__setattr__(self, "address", self.address.lower())

        if (
            not isinstance(self.block_number, int)
            or isinstance(self.block_number, bool)
            or self.block_number < 0
        ):
            raise OnchainTargetError("block_number_invalid")
        if not isinstance(self.block_hash, str) or not _HASH32_RE.fullmatch(self.block_hash):
            raise OnchainTargetError("block_hash_invalid")
        block_hash = self.block_hash.lower()
        if not block_hash.startswith("0x"):
            block_hash = "0x" + block_hash
        object.__setattr__(self, "block_hash", block_hash)

        for field_name in ("runtime_code_sha256",):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
                raise OnchainTargetError(f"{field_name}_invalid")
            object.__setattr__(self, field_name, value.lower())

        if not isinstance(self.source_provider, str) or not self.source_provider.strip():
            raise OnchainTargetError("source_provider_required")
        for field_name in ("compiler_version", "contract_name"):
            if not isinstance(getattr(self, field_name), str):
                raise OnchainTargetError(f"{field_name}_invalid")
        if self.proxy_type is not None and not isinstance(self.proxy_type, str):
            raise OnchainTargetError("proxy_type_invalid")

        implementations = self.implementations
        if isinstance(implementations, list):
            implementations = tuple(implementations)
            object.__setattr__(self, "implementations", implementations)
        if not isinstance(implementations, tuple):
            raise OnchainTargetError("implementations_invalid")
        normalized_implementations = []
        for address in implementations:
            if not isinstance(address, str) or not _ADDRESS_RE.fullmatch(address):
                raise OnchainTargetError("implementation_address_invalid")
            normalized_implementations.append(address.lower())
        object.__setattr__(self, "implementations", tuple(normalized_implementations))

        files = _validate_source_files(self.source_files)
        object.__setattr__(self, "source_files", files)
        actual_source_sha256 = hashlib.sha256(
            _canonical_json(files).encode("utf-8")
        ).hexdigest()
        if self.source_sha256:
            if (
                not isinstance(self.source_sha256, str)
                or not re.fullmatch(r"[0-9a-fA-F]{64}", self.source_sha256)
                or self.source_sha256.lower() != actual_source_sha256
            ):
                raise OnchainTargetError("source_sha256_mismatch")
        object.__setattr__(self, "source_sha256", actual_source_sha256)

        identity = {
            "chain_id": self.chain_id,
            "address": self.address,
            "block_number": self.block_number,
            "block_hash": self.block_hash,
            "runtime_code_sha256": self.runtime_code_sha256,
            "source_sha256": self.source_sha256,
            "source_provider": self.source_provider,
            "compiler_version": self.compiler_version,
            "contract_name": self.contract_name,
            "proxy_type": self.proxy_type,
            "implementations": list(self.implementations),
        }
        object.__setattr__(
            self,
            "target_id",
            hashlib.sha256(_canonical_json(identity).encode("utf-8")).hexdigest(),
        )


class OnchainTargetStore:
    """Insert-only SQLite store for immutable on-chain target snapshots."""

    def __init__(self, db: sqlite3.Connection):
        if not isinstance(db, sqlite3.Connection):
            raise OnchainTargetError("sqlite_connection_required")
        self.db = db
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS onchain_targets (
                target_id TEXT PRIMARY KEY,
                chain_id INTEGER NOT NULL,
                address TEXT NOT NULL,
                block_number INTEGER NOT NULL,
                block_hash TEXT NOT NULL,
                runtime_code_sha256 TEXT NOT NULL,
                source_sha256 TEXT NOT NULL,
                source_provider TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                source_files_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (chain_id, address, block_hash)
            )
        """)
        self.db.execute("""
            CREATE INDEX IF NOT EXISTS idx_onchain_targets_address_block
            ON onchain_targets(chain_id, address, block_number DESC)
        """)
        self.db.commit()

    @staticmethod
    def _metadata(record: OnchainTargetRecord) -> dict:
        return {
            "compiler_version": record.compiler_version,
            "contract_name": record.contract_name,
            "proxy_type": record.proxy_type,
            "implementations": list(record.implementations),
        }

    def put(self, record: OnchainTargetRecord) -> str:
        if not isinstance(record, OnchainTargetRecord):
            raise OnchainTargetError("onchain_target_record_required")
        metadata_json = _canonical_json(self._metadata(record))
        source_files_json = _canonical_json(record.source_files)
        with self.db:
            existing = self.db.execute(
                """
                SELECT target_id, runtime_code_sha256, source_sha256,
                       source_provider, metadata_json, source_files_json
                FROM onchain_targets
                WHERE chain_id = ? AND address = ? AND block_hash = ?
                """,
                (record.chain_id, record.address, record.block_hash),
            ).fetchone()
            if existing is not None:
                expected = (
                    record.target_id,
                    record.runtime_code_sha256,
                    record.source_sha256,
                    record.source_provider,
                    metadata_json,
                    source_files_json,
                )
                if tuple(existing) != expected:
                    raise OnchainTargetError("onchain_target_immutable_conflict")
                return record.target_id

            self.db.execute(
                """
                INSERT INTO onchain_targets (
                    target_id, chain_id, address, block_number, block_hash,
                    runtime_code_sha256, source_sha256, source_provider,
                    metadata_json, source_files_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.target_id,
                    record.chain_id,
                    record.address,
                    record.block_number,
                    record.block_hash,
                    record.runtime_code_sha256,
                    record.source_sha256,
                    record.source_provider,
                    metadata_json,
                    source_files_json,
                ),
            )
        return record.target_id

    @staticmethod
    def _from_row(row) -> OnchainTargetRecord:
        (
            _target_id,
            chain_id,
            address,
            block_number,
            block_hash,
            runtime_code_sha256,
            source_sha256,
            source_provider,
            metadata_json,
            source_files_json,
        ) = row
        metadata = json.loads(metadata_json)
        return OnchainTargetRecord(
            chain_id=chain_id,
            address=address,
            block_number=block_number,
            block_hash=block_hash,
            runtime_code_sha256=runtime_code_sha256,
            source_sha256=source_sha256,
            source_provider=source_provider,
            source_files=json.loads(source_files_json),
            compiler_version=metadata["compiler_version"],
            contract_name=metadata["contract_name"],
            proxy_type=metadata["proxy_type"],
            implementations=tuple(metadata["implementations"]),
        )

    def get(self, target_id: str) -> OnchainTargetRecord | None:
        if not isinstance(target_id, str) or not target_id:
            return None
        row = self.db.execute(
            """
            SELECT target_id, chain_id, address, block_number, block_hash,
                   runtime_code_sha256, source_sha256, source_provider,
                   metadata_json, source_files_json
            FROM onchain_targets WHERE target_id = ?
            """,
            (target_id,),
        ).fetchone()
        return self._from_row(row) if row is not None else None

    def find_latest(self, chain_id: int, address: str) -> OnchainTargetRecord | None:
        if (
            not isinstance(chain_id, int)
            or isinstance(chain_id, bool)
            or chain_id <= 0
            or not isinstance(address, str)
            or not _ADDRESS_RE.fullmatch(address)
        ):
            raise OnchainTargetError("target_lookup_coordinates_invalid")
        row = self.db.execute(
            """
            SELECT target_id, chain_id, address, block_number, block_hash,
                   runtime_code_sha256, source_sha256, source_provider,
                   metadata_json, source_files_json
            FROM onchain_targets
            WHERE chain_id = ? AND address = ?
            ORDER BY block_number DESC, created_at DESC
            LIMIT 1
            """,
            (chain_id, address.lower()),
        ).fetchone()
        return self._from_row(row) if row is not None else None

    def count(self) -> int:
        return int(self.db.execute("SELECT COUNT(*) FROM onchain_targets").fetchone()[0])
