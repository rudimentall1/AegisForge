"""Bounded structural analysis for Solidity source bundles.

This is a source-triage aid, not a compiler AST, proof of bytecode equivalence,
or vulnerability verdict. It deliberately fails closed on malformed bodies.
"""
from __future__ import annotations

import hashlib
import re
from typing import Dict, Iterable, List, Tuple


_FUNCTION_RE = re.compile(
    r"\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)([^;{}]*)\{"
)
_MODIFIER_RE = re.compile(r"\bmodifier\s+([A-Za-z_]\w*)\s*\([^)]*\)[^;{}]*\{")
_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_EXTERNAL_CALL_RE = re.compile(r"\.\s*(delegatecall|staticcall|call|transfer|send)\b")
_ASSIGNMENT_RE_TEMPLATE = r"\b{0}\b\s*(?:\[[^\]]+\]\s*)?(?:=|\+=|-=|\*=|/=|\+\+|--)"
_AUTH_NAME_RE = re.compile(r"(?:only|owner|admin|role|auth|permission|manager|operator)", re.I)
_AUTH_CHECK_RE = re.compile(
    r"\b(?:require|assert)\s*\([^;]*(?:msg\s*\.\s*sender|tx\s*\.\s*origin)"
    r"[^;]*(?:owner|admin|role|authorized|authority)",
    re.I,
)
_IGNORED_CALLS = {
    "if", "for", "while", "do", "switch", "catch", "returns", "emit",
    "require", "assert", "revert", "keccak256", "sha256", "ripemd160",
    "ecrecover", "abi", "type", "new", "delete", "payable", "address",
    "uint", "uint8", "uint16", "uint32", "uint64", "uint128", "uint256",
    "int", "int8", "int16", "int32", "int64", "int128", "int256",
    "bytes", "bytes4", "bytes8", "bytes16", "bytes32", "string", "bool",
}


def _mask_non_code(source: str) -> str:
    """Replace comments and quoted literals with spaces, preserving offsets/lines."""
    out = list(source)
    i = 0
    state = "code"
    quote = ""
    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                out[i] = out[i + 1] = " "
                i += 2
                state = "line_comment"
                continue
            if ch == "/" and nxt == "*":
                out[i] = out[i + 1] = " "
                i += 2
                state = "block_comment"
                continue
            if ch in ("'", '"'):
                quote = ch
                out[i] = " "
                state = "string"
        elif state == "line_comment":
            if ch == "\n":
                state = "code"
            else:
                out[i] = " "
        elif state == "block_comment":
            if ch == "*" and nxt == "/":
                out[i] = out[i + 1] = " "
                i += 2
                state = "code"
                continue
            if ch != "\n":
                out[i] = " "
        elif state == "string":
            if ch == "\\":
                if ch != "\n":
                    out[i] = " "
                if i + 1 < len(source):
                    if source[i + 1] != "\n":
                        out[i + 1] = " "
                    i += 2
                    continue
            elif ch == quote:
                out[i] = " "
                state = "code"
            elif ch != "\n":
                out[i] = " "
        i += 1
    return "".join(out)


def _matching_brace(masked: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _top_level_state_names(masked: str) -> set:
    names = set()
    depth = 0
    start = 0
    for index, char in enumerate(masked):
        if char == "{":
            depth += 1
        elif char == "}":
            depth = max(0, depth - 1)
        elif char == ";" and depth == 1:
            statement = masked[start:index].strip()
            start = index + 1
            if not statement or re.match(
                r"^(?:event|error|using|struct|enum|modifier|function|constructor)\b",
                statement,
            ):
                continue
            match = re.search(
                r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)?(?:=.*)?$", statement
            )
            if match:
                names.add(match.group(1))
        elif char == "{" and depth == 1:
            # A contract-level function/modifier/struct body is not a state declaration.
            start = index + 1
    return names


def _extract_blocks(source: str, masked: str, pattern: re.Pattern, kind: str):
    blocks = []
    errors = []
    for match in pattern.finditer(masked):
        opening = match.end() - 1
        closing = _matching_brace(masked, opening)
        name = match.group(1)
        if closing < 0:
            errors.append({
                "kind": kind,
                "name": name,
                "line": _line_number(source, match.start()),
                "error": "unbalanced_body",
            })
            continue
        blocks.append({
            "name": name,
            "line": _line_number(source, match.start()),
            "header": source[match.start():opening],
            "body": source[opening + 1:closing],
            "masked_body": masked[opening + 1:closing],
        })
    return blocks, errors


def analyze_solidity_sources(source_files: Dict[str, str]) -> dict:
    """Inventory functions, modifiers, local call edges and risk-relevant signals."""
    if not isinstance(source_files, dict):
        raise TypeError("source_files_must_be_mapping")
    if len(source_files) > 500:
        raise ValueError("source_file_limit_exceeded")

    files = []
    all_functions = []
    errors = []
    for path, source in sorted(source_files.items()):
        if not isinstance(path, str) or not isinstance(source, str):
            errors.append({"path": str(path), "error": "invalid_source_record"})
            continue
        if len(source.encode("utf-8")) > 4 * 1024 * 1024:
            errors.append({"path": path, "error": "source_file_too_large"})
            continue
        masked = _mask_non_code(source)
        function_blocks, function_errors = _extract_blocks(
            source, masked, _FUNCTION_RE, "function"
        )
        modifier_blocks, modifier_errors = _extract_blocks(
            source, masked, _MODIFIER_RE, "modifier"
        )
        errors.extend(dict(item, path=path) for item in function_errors + modifier_errors)
        state_names = _top_level_state_names(masked)
        file_functions = []
        for block in function_blocks:
            header = re.sub(r"\breturns\s*\([^)]*\)", " ", block["header"])
            parameter_end = header.find(")")
            modifier_tail = header[parameter_end + 1:] if parameter_end >= 0 else ""
            modifier_names = re.findall(
                r"\b([A-Za-z_]\w*)\s*(?:\([^)]*\))?",
                modifier_tail,
            )
            modifier_names = [
                name for name in modifier_names
                if name not in {
                    "public", "external", "internal", "private", "pure",
                    "view", "payable", "virtual", "override", "returns",
                    "memory", "calldata", "storage",
                }
            ]
            external_calls = []
            for call in _EXTERNAL_CALL_RE.finditer(block["masked_body"]):
                name = call.group(1)
                if name not in external_calls:
                    external_calls.append(name)
            writes = []
            for name in sorted(state_names):
                if re.search(_ASSIGNMENT_RE_TEMPLATE.format(re.escape(name)), block["masked_body"]):
                    writes.append(name)
            auth_signals = []
            for name in modifier_names:
                if _AUTH_NAME_RE.search(name):
                    auth_signals.append({
                        "kind": "authorization_modifier",
                        "name": name,
                        "line": block["line"],
                    })
            for auth_match in _AUTH_CHECK_RE.finditer(block["masked_body"]):
                auth_signals.append({
                    "kind": "inline_sender_check",
                    "line": block["line"] + block["masked_body"][:auth_match.start()].count("\n"),
                })
            raw_calls = []
            for call in _CALL_RE.finditer(block["masked_body"]):
                name = call.group(1)
                if name not in _IGNORED_CALLS and name not in raw_calls:
                    raw_calls.append(name)
            visibility_match = re.search(r"\b(public|external|internal|private)\b", header)
            mutability_match = re.search(r"\b(pure|view|payable)\b", header)
            record = {
                "path": path,
                "name": block["name"],
                "line": block["line"],
                "visibility": visibility_match.group(1) if visibility_match else "default",
                "mutability": mutability_match.group(1) if mutability_match else "nonpayable",
                "modifiers": modifier_names,
                "_raw_calls": raw_calls,
                "calls": [],
                "external_calls": external_calls,
                "state_write_candidates": writes,
                "authorization_signals": auth_signals,
                "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
            }
            file_functions.append(record)
            all_functions.append(record)
        files.append({
            "path": path,
            "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
            "functions": len(file_functions),
            "modifiers": [item["name"] for item in modifier_blocks],
        })

    known_functions = {item["name"] for item in all_functions}
    known_modifiers = {
        name for item in files for name in item["modifiers"]
    }
    for function in all_functions:
        raw_calls = function.pop("_raw_calls", [])
        function["calls"] = [
            name for name in raw_calls if name in known_functions
        ]
        function["unresolved_calls"] = [
            name for name in raw_calls
            if name not in known_functions and name not in known_modifiers
        ][:100]

    call_graph = [
        {
            "path": item["path"],
            "function": item["name"],
            "calls": item["calls"],
        }
        for item in all_functions
    ]
    return {
        "schema_version": 1,
        "analysis_complete": not errors,
        "files": files,
        "functions": all_functions,
        "call_graph": call_graph,
        "summary": {
            "files_analyzed": len(files),
            "functions_analyzed": len(all_functions),
            "call_edges": sum(len(item["calls"]) for item in all_functions),
            "functions_with_external_calls": sum(bool(item["external_calls"]) for item in all_functions),
            "functions_with_state_write_candidates": sum(bool(item["state_write_candidates"]) for item in all_functions),
            "functions_with_authorization_signals": sum(bool(item["authorization_signals"]) for item in all_functions),
        },
        "errors": errors,
        "analysis_limits": {
            "method": "bounded lexical Solidity structural analysis",
            "compiler_ast": False,
            "bytecode_equivalence_verified": False,
            "vulnerabilities_confirmed": 0,
            "finding_created": False,
        },
    }
