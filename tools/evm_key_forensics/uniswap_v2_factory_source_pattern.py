#!/usr/bin/env python3
"""Offline source-pattern check for the pinned, explorer-verified Uniswap V2 Factory.

This verifies local source provenance and two source-level authorization checks.
It does not query Ethereum, compile Solidity, execute the EVM, or independently
verify the deployed bytecode. The manifest records the explorer's reported status.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

SCHEMA_VERSION = "aegisforge-uniswap-v2-factory-observation-v1"
PINNED_REPOSITORY = "Uniswap/v2-core"
PINNED_COMMIT = "4dd59067c76dea4a0e8e4bfdda41877a6b16dedc"
PINNED_PATH = "contracts/UniswapV2Factory.sol"
PINNED_GIT_BLOB_SHA1 = "a66ad8247b88cbd4e547b0f9dee8fceede51a358"
CHAIN_ID = 1
CONTRACT_ADDRESS = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"
EXPLORER_URL = "https://etherscan.io/address/0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f"
MAX_SOURCE_BYTES = 64 * 1024


def git_blob_sha1(source_bytes: bytes) -> str:
    return hashlib.sha1(
        f"blob {len(source_bytes)}\0".encode("ascii") + source_bytes
    ).hexdigest()


def mask_comments_and_strings(source: str) -> str:
    """Mask comments and string literals without changing source offsets."""
    pattern = re.compile(
        r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\])*\"|"
        r"'(?:\\.|[^'\\])*'",
        re.DOTALL,
    )
    return pattern.sub(
        lambda match: re.sub(r"[^\n]", " ", match.group(0)),
        source,
    )


def _function_body(source: str, name: str) -> str | None:
    match = re.search(
        r"\bfunction\s+" + re.escape(name) + r"\s*\([^)]*\)\s*external\b(?P<body>.*?)\n\s*\}",
        source,
        re.DOTALL,
    )
    return match.group("body") if match else None


def _authorized_before_assignment(body: str | None, assignment: str) -> bool:
    if body is None:
        return False
    authorization = re.search(
        r"\brequire\s*\(\s*msg\s*\.\s*sender\s*==\s*feeToSetter\s*,",
        body,
    )
    mutation = re.search(assignment, body)
    return authorization is not None and mutation is not None and authorization.start() < mutation.start()


def inspect_source(
    source: str,
    *,
    source_commit: str = PINNED_COMMIT,
    source_path: str = PINNED_PATH,
    expected_git_blob_sha1: str = PINNED_GIT_BLOB_SHA1,
) -> dict:
    raw = source.encode("utf-8")
    actual_blob = git_blob_sha1(raw)
    errors = []
    if len(raw) > MAX_SOURCE_BYTES:
        errors.append("source_size_limit_exceeded")
    if source_commit != PINNED_COMMIT:
        errors.append("source_commit_not_allowlisted")
    if source_path != PINNED_PATH:
        errors.append("source_path_not_allowlisted")
    if expected_git_blob_sha1 != PINNED_GIT_BLOB_SHA1 or actual_blob != PINNED_GIT_BLOB_SHA1:
        errors.append("pinned_git_blob_mismatch")

    masked = mask_comments_and_strings(source)
    set_fee_to = _function_body(masked, "setFeeTo")
    set_fee_to_setter = _function_body(masked, "setFeeToSetter")
    checks = {
        "factory_contract_present": bool(re.search(r"\bcontract\s+UniswapV2Factory\b", masked)),
        "fee_to_setter_state_present": bool(
            re.search(r"\baddress\s+public\s+feeToSetter\s*;", masked)
        ),
        "constructor_initializes_fee_to_setter": bool(
            re.search(
                r"\bconstructor\s*\(\s*address\s+_feeToSetter\s*\)\s*public\s*\{\s*feeToSetter\s*=\s*_feeToSetter\s*;",
                masked,
            )
        ),
        "set_fee_to_authorized_before_assignment": _authorized_before_assignment(
            set_fee_to, r"\bfeeTo\s*=\s*_feeTo\s*;"
        ),
        "set_fee_to_setter_authorized_before_assignment": _authorized_before_assignment(
            set_fee_to_setter, r"\bfeeToSetter\s*=\s*_feeToSetter\s*;"
        ),
        "tx_origin_absent_from_code": not bool(
            re.search(r"\btx\s*\.\s*origin\b", masked)
        ),
    }
    if not all(checks.values()):
        errors.append("expected_factory_authorization_pattern_not_observed")

    conclusion = "SOURCE_PATTERN_MATCHED" if not errors else "INCONCLUSIVE"
    return {
        "schema_version": SCHEMA_VERSION,
        "target_id": "uniswap-v2-factory-mainnet",
        "repository": PINNED_REPOSITORY,
        "source_commit": source_commit,
        "source_path": source_path,
        "source_git_blob_sha1": actual_blob,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "source_bytes": len(raw),
        "chain_id": CHAIN_ID,
        "contract_address": CONTRACT_ADDRESS,
        "explorer_verification_reference": EXPLORER_URL,
        "checks": checks,
        "conclusion": conclusion,
        "errors": errors,
        "finding": False,
        "vulnerability_confirmed": False,
        "explorer_checked_at_runtime": False,
        "rpc_used": False,
        "source_executed": False,
        "interpretation": (
            "This observation checks a pinned source snapshot and the source-level "
            "feeToSetter authorization pattern only. The provenance manifest records "
            "Etherscan's reported exact-match status; this script does not independently "
            "verify deployed bytecode or establish that the contract is safe."
        ),
    }


def main(argv=None) -> int:
    default_source = (
        Path(__file__).resolve().parents[2]
        / "tests" / "fixtures" / "solidity" / "UniswapV2Factory.sol"
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", nargs="?", type=Path, default=default_source)
    parser.add_argument("--commit", default=PINNED_COMMIT)
    parser.add_argument("--path", default=PINNED_PATH)
    parser.add_argument("--expected-git-blob-sha1", default=PINNED_GIT_BLOB_SHA1)
    args = parser.parse_args(argv)
    try:
        raw = args.source.read_bytes()
        if len(raw) > MAX_SOURCE_BYTES:
            result = inspect_source(
                "", source_commit=args.commit, source_path=args.path,
                expected_git_blob_sha1=args.expected_git_blob_sha1,
            )
            result["errors"] = ["source_size_limit_exceeded"]
            result["conclusion"] = "INCONCLUSIVE"
        else:
            result = inspect_source(
                raw.decode("utf-8"),
                source_commit=args.commit,
                source_path=args.path,
                expected_git_blob_sha1=args.expected_git_blob_sha1,
            )
    except (OSError, UnicodeDecodeError) as exc:
        result = {
            "schema_version": SCHEMA_VERSION,
            "conclusion": "INCONCLUSIVE",
            "errors": [f"source_read_failed:{type(exc).__name__}"],
            "finding": False,
            "vulnerability_confirmed": False,
        }
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("conclusion") == "SOURCE_PATTERN_MATCHED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
