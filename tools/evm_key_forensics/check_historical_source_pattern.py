#!/usr/bin/env python3
"""Offline source-pattern checker; does not compile or execute historical code."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

SCHEMA_VERSION = 1
EXPERIMENT_ID = "evm-forensics-historical-source-pattern-v1"
UPSTREAM_COMMIT = "0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6"


def _find_function_body(source: str, start: int) -> tuple[int | None, int | None]:
    """Find balanced C++ braces while ignoring comments and quoted literals."""
    brace_start = None
    depth = 0
    state = "code"
    escaped = False
    index = start
    while index < len(source):
        char = source[index]
        nxt = source[index + 1] if index + 1 < len(source) else ""

        if state == "line_comment":
            if char == "\n":
                state = "code"
        elif state == "block_comment":
            if char == "*" and nxt == "/":
                state = "code"
                index += 1
        elif state in {"string", "char"}:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif (state == "string" and char == '"') or (state == "char" and char == "'"):
                state = "code"
        else:
            if char == "/" and nxt == "/":
                state = "line_comment"
                index += 1
            elif char == "/" and nxt == "*":
                state = "block_comment"
                index += 1
            elif char == '"':
                state = "string"
            elif char == "'":
                state = "char"
            elif char == "{" :
                if brace_start is None:
                    brace_start = index
                depth += 1
            elif char == "}":
                if brace_start is None:
                    return None, None
                depth -= 1
                if depth == 0:
                    return brace_start, index + 1
                if depth < 0:
                    return brace_start, None
        index += 1
    return brace_start, None


def inspect_source(source: str) -> dict:
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    marker = "cl_ulong4 Dispatcher::Device::createSeed()"
    start = source.find(marker)
    if start < 0:
        return _result("INCONCLUSIVE", digest, ["createSeed_function_missing"])

    # Scope the check to the function body; braces in comments and quoted
    # literals must not alter the parser's nesting depth.
    brace_start, end = _find_function_body(source, start)
    if brace_start is None:
        return _result("INCONCLUSIVE", digest, ["function_body_missing"])
    if end is None:
        return _result("INCONCLUSIVE", digest, ["function_body_unbalanced"])

    body = source[brace_start:end]
    errors = []
    debug_pos = body.find("#ifdef PROFANITY_DEBUG")
    else_pos = body.find("#else", debug_pos + 1) if debug_pos >= 0 else -1
    endif_pos = body.find("#endif", else_pos + 1) if else_pos >= 0 else -1
    if min(debug_pos, else_pos, endif_pos) < 0:
        return _result("INCONCLUSIVE", digest, ["debug_branch_structure_ambiguous"])

    debug_branch = body[debug_pos:else_pos]
    production_branch = body[else_pos:endif_pos]

    if len(re.findall(r"std\s*::\s*random_device\s+rd\s*;", production_branch)) != 1:
        errors.append("expected_single_random_device_declaration")
    if len(re.findall(r"\brd\s*\(\s*\)", production_branch)) != 1:
        errors.append("expected_single_random_device_call")
    if len(re.findall(r"std\s*::\s*mt19937_64\s+eng\s*\(\s*rd\s*\(\s*\)\s*\)", production_branch)) != 1:
        errors.append("expected_single_mt19937_64_initialization_from_rd")
    if len(re.findall(r"\bdistr\s*\(\s*eng\s*\)", production_branch)) != 4:
        errors.append("expected_four_distribution_calls")
    for word_index in range(4):
        assignment = rf"r\s*\.\s*s\s*\[\s*{word_index}\s*\]\s*=\s*distr\s*\(\s*eng\s*\)\s*;"
        if len(re.findall(assignment, production_branch)) != 1:
            errors.append(f"expected_one_distribution_assignment_for_word_{word_index}")

    if "std::random_device rd;" in debug_branch or "std::mt19937_64" in debug_branch:
        errors.append("debug_branch_contains_unexpected_random_engine")
    for word_index in range(4):
        fixed_assignment = rf"r\s*\.\s*s\s*\[\s*{word_index}\s*\]\s*=\s*1\s*;"
        if len(re.findall(fixed_assignment, debug_branch)) != 1:
            errors.append(f"debug_fixed_seed_word_{word_index}_not_recognized")

    return _result("SOURCE_PATTERN_MATCHED" if not errors else "INCONCLUSIVE", digest, errors)


def _result(conclusion: str, source_sha256: str, errors: list[str]) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "experiment_id": EXPERIMENT_ID,
        "upstream_repository": "https://github.com/johguse/profanity",
        "expected_upstream_commit": UPSTREAM_COMMIT,
        "source_sha256": source_sha256,
        "conclusion": conclusion,
        "errors": errors,
        "historical_code_executed": False,
        "wallet_material_used": False,
        "historical_vulnerability_reproduced": False,
        "interpretation": (
            "A source-pattern match only supports the reviewed source-semantics "
            "statement; it does not establish source provenance, runtime behavior, "
            "entropy, exploitability, or wallet compromise."
        ),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_file", type=Path, help="locally obtained source file; never downloaded by this tool")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args(argv)
    try:
        source = args.source_file.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        result = _result("INCONCLUSIVE", "", [f"source_unreadable:{type(exc).__name__}"])
    else:
        result = inspect_source(source)
    print(json.dumps(result, sort_keys=True, indent=2 if args.pretty else None))
    return 0 if result["conclusion"] == "SOURCE_PATTERN_MATCHED" else 2


if __name__ == "__main__":
    sys.exit(main())
