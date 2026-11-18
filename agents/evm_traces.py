"""Parsers for parity/OpenEthereum and Geth callTracer deployment traces."""

import re


_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_TX_HASH_RE = re.compile(r"^0x[a-fA-F0-9]{64}$")
_CREATE_TYPES = {"create", "create2"}


def _valid_address(value):
    return isinstance(value, str) and _ADDRESS_RE.fullmatch(value) is not None


def _valid_tx_hash(value):
    return isinstance(value, str) and _TX_HASH_RE.fullmatch(value) is not None


def _valid_trace_path(value):
    return (
        isinstance(value, list)
        and all(type(index) is int and index >= 0 for index in value)
    )


def _parity_creations(traces):
    findings = []
    seen = set()
    failed_paths = {
        tuple(trace.get("traceAddress", ()))
        for trace in traces
        if isinstance(trace, dict)
        and trace.get("error")
        and _valid_trace_path(trace.get("traceAddress"))
    }
    for trace in traces:
        if not isinstance(trace, dict) or str(trace.get("type", "")).lower() != "create":
            continue
        trace_address = trace.get("traceAddress")
        action = trace.get("action")
        result = trace.get("result")
        tx_hash = trace.get("transactionHash") or trace.get("txHash")
        if not _valid_trace_path(trace_address) or not trace_address:
            continue
        if any(
            tuple(trace_address[:depth]) in failed_paths
            for depth in range(len(trace_address) + 1)
        ):
            continue
        if not isinstance(action, dict) or not isinstance(result, dict):
            continue
        address = result.get("address")
        creator = action.get("from")
        if not (_valid_address(address) and _valid_address(creator) and _valid_tx_hash(tx_hash)):
            continue
        key = (tx_hash.lower(), address.lower(), tuple(trace_address))
        if key in seen:
            continue
        seen.add(key)
        method = str(action.get("creationMethod") or "create").lower()
        if method not in _CREATE_TYPES:
            method = "create"
        findings.append({
            "contract_address": address,
            "transaction_hash": tx_hash,
            "deployer": creator,
            "creation_method": method,
            "trace_address": list(trace_address),
        })
    return findings


def _geth_creations(transactions):
    findings = []
    seen = set()

    def visit(node, tx_hash, path):
        if not isinstance(node, dict) or node.get("error"):
            return
        node_type = str(node.get("type", "")).lower()
        if path and node_type in _CREATE_TYPES:
            address = node.get("to") or node.get("address")
            creator = node.get("from")
            if _valid_address(address) and _valid_address(creator) and _valid_tx_hash(tx_hash):
                key = (tx_hash.lower(), address.lower(), tuple(path))
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "contract_address": address,
                        "transaction_hash": tx_hash,
                        "deployer": creator,
                        "creation_method": node_type,
                        "trace_address": list(path),
                    })
        children = node.get("calls")
        if isinstance(children, list):
            for index, child in enumerate(children):
                visit(child, tx_hash, path + [index])

    for transaction in transactions:
        if not isinstance(transaction, dict):
            continue
        tx_hash = transaction.get("txHash") or transaction.get("transactionHash")
        root = transaction.get("result")
        if _valid_tx_hash(tx_hash) and isinstance(root, dict):
            visit(root, tx_hash, [])
    return findings


def extract_internal_creations(response):
    """Return validated internal CREATE/CREATE2 events from an RPC trace response.

    Root transaction creation is intentionally excluded; the block scanner
    already handles it from the transaction receipt.
    """
    if not isinstance(response, dict) or response.get("error") is not None:
        return []
    traces = response.get("result")
    if not isinstance(traces, list):
        return []
    if any(
        isinstance(item, dict)
        and "action" in item
        and "traceAddress" in item
        for item in traces
    ):
        return _parity_creations(traces)
    return _geth_creations(traces)
