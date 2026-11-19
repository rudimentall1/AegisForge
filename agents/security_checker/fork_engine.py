"""Deterministic, hash-pinned inputs for isolated EVM fork research.

This module validates observations obtained through the read-only RPC gateway.
It does not start Anvil, contact an RPC provider, or execute transactions.
"""
from __future__ import annotations

import hashlib
import json
import re

from agents.security_checker.rpc_gateway import (
    RpcGatewayError,
    forward_rpc_request,
    validate_fork_anchor,
)


_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
_HASH_RE = re.compile(r"0x[0-9a-fA-F]{64}")
_BYTECODE_RE = re.compile(r"0x(?:[0-9a-fA-F]{2})+")
_QUANTITY_RE = re.compile(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)")

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
    """Validate and normalize a chain/block/contract execution snapshot."""
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


def _response_id(response: object, expected_id: object, label: str) -> None:
    if (
        not isinstance(response, dict)
        or response.get("jsonrpc") != "2.0"
        or "error" in response
        or response.get("id") != expected_id
        or isinstance(response.get("id"), bool)
        or "result" not in response
    ):
        raise ForkSnapshotError(f"{label}_response_invalid")


def build_fork_snapshot_from_rpc(
    *,
    chain_response: dict,
    block_response: dict,
    code_response: dict,
    code_request: dict,
    expected_chain_id: int,
    expected_block_number: int,
    expected_block_hash: str,
    contract_address: str,
    expected_response_ids: tuple,
) -> dict:
    """Build a snapshot only from matching response IDs and pinned code request.

    The caller passes the normalized eth_getCode request sent through the
    read-only gateway. This prevents labeling latest-state code as historical.
    """
    if (
        not isinstance(expected_response_ids, tuple)
        or len(expected_response_ids) != 3
        or any(
            isinstance(value, bool)
            or not isinstance(value, (int, str))
            or (isinstance(value, str) and (not value or len(value) > 128))
            for value in expected_response_ids
        )
        or len(set(expected_response_ids)) != 3
    ):
        raise ForkSnapshotError("rpc_response_ids_invalid")

    chain_id_response_id, block_response_id, code_response_id = expected_response_ids
    _response_id(chain_response, chain_id_response_id, "chain")
    _response_id(block_response, block_response_id, "block")
    _response_id(code_response, code_response_id, "code")

    if (
        not isinstance(code_request, dict)
        or set(code_request) != {"jsonrpc", "id", "method", "params"}
        or code_request.get("jsonrpc") != "2.0"
        or code_request.get("id") != code_response_id
        or isinstance(code_request.get("id"), bool)
        or code_request.get("method") != "eth_getCode"
    ):
        raise ForkSnapshotError("code_request_invalid")

    params = code_request.get("params")
    if (
        not isinstance(params, list)
        or len(params) != 2
        or not isinstance(params[0], str)
        or not _ADDRESS_RE.fullmatch(params[0])
        or not isinstance(params[1], str)
        or not _QUANTITY_RE.fullmatch(params[1])
    ):
        raise ForkSnapshotError("code_request_invalid")

    if (
        not isinstance(contract_address, str)
        or not _ADDRESS_RE.fullmatch(contract_address)
        or params[0].lower() != contract_address.lower()
    ):
        raise ForkSnapshotError("code_request_address_mismatch")

    expected_tag = hex(expected_block_number) if (
        isinstance(expected_block_number, int)
        and not isinstance(expected_block_number, bool)
        and expected_block_number >= 0
    ) else None
    if params[1].lower() != expected_tag:
        raise ForkSnapshotError("code_request_block_mismatch")

    try:
        anchor = validate_fork_anchor(
            chain_response=chain_response,
            block_response=block_response,
            expected_chain_id=expected_chain_id,
            expected_block_number=expected_block_number,
            expected_block_hash=expected_block_hash,
        )
    except RpcGatewayError as exc:
        raise ForkSnapshotError(str(exc)) from exc

    return build_fork_snapshot(
        chain_id=anchor["chain_id"],
        block_number=anchor["block_number"],
        block_hash=anchor["block_hash"],
        contract_address=contract_address,
        runtime_bytecode=code_response["result"],
    )


def collect_fork_snapshot(
    *,
    upstream_url: str,
    allowed_hosts: set[str],
    expected_chain_id: int,
    block_number: int,
    contract_address: str,
) -> dict:
    """Collect chain, historical block, and historical code via the RPC gateway.

    All upstream requests are read-only JSON-RPC calls. The block height is
    explicit, and eth_getCode is queried at that same height, never at latest.
    """
    if (
        isinstance(expected_chain_id, bool)
        or not isinstance(expected_chain_id, int)
        or expected_chain_id <= 0
    ):
        raise ForkSnapshotError("chain_id_invalid")
    if (
        isinstance(block_number, bool)
        or not isinstance(block_number, int)
        or block_number < 0
    ):
        raise ForkSnapshotError("block_number_invalid")
    if (
        not isinstance(contract_address, str)
        or not _ADDRESS_RE.fullmatch(contract_address)
    ):
        raise ForkSnapshotError("contract_address_invalid")

    block_tag = hex(block_number)
    requests = (
        {
            "jsonrpc": "2.0",
            "id": "aegisforge-chain-id",
            "method": "eth_chainId",
            "params": [],
        },
        {
            "jsonrpc": "2.0",
            "id": "aegisforge-block",
            "method": "eth_getBlockByNumber",
            "params": [block_tag, False],
        },
        {
            "jsonrpc": "2.0",
            "id": "aegisforge-code",
            "method": "eth_getCode",
            "params": [contract_address.lower(), block_tag],
        },
    )

    responses = []
    try:
        for request in requests:
            response = forward_rpc_request(
                upstream_url,
                allowed_hosts,
                json.dumps(request, separators=(",", ":")).encode("utf-8"),
            )
            responses.append(response)
    except RpcGatewayError as exc:
        raise ForkSnapshotError("rpc_gateway_rejected_snapshot_request") from exc

    block_result = (
        responses[1].get("result")
        if isinstance(responses[1], dict)
        else None
    )
    block_hash = block_result.get("hash") if isinstance(block_result, dict) else None

    return build_fork_snapshot_from_rpc(
        chain_response=responses[0],
        block_response=responses[1],
        code_response=responses[2],
        code_request=requests[2],
        expected_chain_id=expected_chain_id,
        expected_block_number=block_number,
        expected_block_hash=block_hash,
        contract_address=contract_address,
        expected_response_ids=tuple(request["id"] for request in requests),
    )
