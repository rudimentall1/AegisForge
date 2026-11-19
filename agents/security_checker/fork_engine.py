"""Deterministic, hash-pinned inputs for isolated EVM fork research.

This module deliberately does not start Anvil or contact an RPC provider. It
validates and fingerprints observations obtained through the read-only RPC
gateway so later fork orchestration can consume a stable snapshot contract.
"""
from __future__ import annotations

import hashlib
import re


_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
_HASH_RE = re.compile(r"0x[0-9a-fA-F]{64}")
_BYTECODE_RE = re.compile(r"0x(?:[0-9a-fA-F]{2})+")

MAX_RUNTIME_BYTECODE_BYTES = 24_576


class ForkSnapshotError(ValueError):
    """A fork snapshot contains invalid or incomplete chain observations."""


def build_fork_snapshot(
    *,
    chain_id: int,
    block_number: int,
    block_hash: str,
    contract_address: str,
    runtime_bytecode: str,
) -> dict:
    """Validate and normalize the chain/block/contract execution snapshot.

    The digest is SHA-256 over decoded runtime bytecode bytes, not over its
    textual hex representation. This makes equivalent hex casing identical.
    """
    if (
        isinstance(chain_id, bool)
        or not isinstance(chain_id, int)
        or chain_id <= 0
    ):
        raise ForkSnapshotError("chain_id_invalid")

    if (
        isinstance(block_number, bool)
        or not isinstance(block_number, int)
        or block_number < 0
    ):
        raise ForkSnapshotError("block_number_invalid")

    if not isinstance(block_hash, str) or not _HASH_RE.fullmatch(block_hash):
        raise ForkSnapshotError("block_hash_invalid")

    if (
        not isinstance(contract_address, str)
        or not _ADDRESS_RE.fullmatch(contract_address)
    ):
        raise ForkSnapshotError("contract_address_invalid")

    if not isinstance(runtime_bytecode, str) or not _BYTECODE_RE.fullmatch(
        runtime_bytecode
    ):
        raise ForkSnapshotError("runtime_bytecode_invalid")

    code_bytes = bytes.fromhex(runtime_bytecode[2:])
    if len(code_bytes) > MAX_RUNTIME_BYTECODE_BYTES:
        raise ForkSnapshotError("runtime_bytecode_too_large")

    return {
        "schema": "aegisforge.fork_snapshot.v1",
        "chain_id": chain_id,
        "block_number": block_number,
        "block_hash": block_hash.lower(),
        "contract_address": contract_address.lower(),
        "runtime_bytecode": "0x" + runtime_bytecode[2:].lower(),
        "runtime_bytecode_sha256": hashlib.sha256(code_bytes).hexdigest(),
    }
