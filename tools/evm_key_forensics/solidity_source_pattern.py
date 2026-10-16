#!/usr/bin/env python3
"""Offline, pinned-source acceptance check for the Solidity fixture.

This is a source-provenance and invariant-presence check, not a vulnerability
scanner, compiler, EVM execution, or proof about any deployed contract.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

SCHEMA_VERSION = "aegisforge-solidity-source-observation-v1"
PINNED_REPOSITORY = "OpenZeppelin/openzeppelin-contracts"
PINNED_COMMIT = "dbb6104ce834628e473d2173bbc9d47f81a9eec3"
PINNED_PATH = "contracts/access/Ownable.sol"
PINNED_GIT_BLOB_SHA1 = "bd96f6661dcbf7b2d4948823ac0e7bfb4ba31fb1"
MAX_SOURCE_BYTES = 128 * 1024


def git_blob_sha1(source_bytes: bytes) -> str:
    return hashlib.sha1(
        f"blob {len(source_bytes)}\0".encode("ascii") + source_bytes
    ).hexdigest()


def mask_comments_and_strings(source: str) -> str:
    """Replace comments and quoted literals while preserving token boundaries."""
    pattern = re.compile(
        r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|'
        r"'(?:\\.|[^'\\])*'",
        re.DOTALL,
    )
    return pattern.sub(lambda match: re.sub(r"[^\n]", " ", match.group(0)), source)


def inspect_source(
    source: str,
    *,
    source_commit: str = PINNED_COMMIT,
    source_path: str = PINNED_PATH,
    expected_git_blob_sha1: str = PINNED_GIT_BLOB_SHA1,
) -> dict:
    source_bytes = source.encode("utf-8")
    digest = hashlib.sha256(source_bytes).hexdigest()
    actual_blob = git_blob_sha1(source_bytes)
    errors = []

    if len(source_bytes) > MAX_SOURCE_BYTES:
        errors.append("source_size_limit_exceeded")
    if source_commit != PINNED_COMMIT:
        errors.append("source_commit_not_allowlisted")
    if source_path != PINNED_PATH:
        errors.append("source_path_not_allowlisted")
    if expected_git_blob_sha1 != PINNED_GIT_BLOB_SHA1 or actual_blob != PINNED_GIT_BLOB_SHA1:
        errors.append("pinned_git_blob_mismatch")

    masked = mask_comments_and_strings(source)
    checks = {
        "owner_modifier_present": bool(re.search(r"\bmodifier\s+onlyOwner\s*\(", masked)),
        "modifier_calls_owner_check": bool(re.search(r"\bmodifier\s+onlyOwner\s*\(\s*\)\s*\{\s*_checkOwner\s*\(\s*\)\s*;", masked)),
        "owner_compared_with_msg_sender": bool(re.search(r"\bowner\s*\(\s*\)\s*!=\s*_msgSender\s*\(\s*\)", masked)),
        "tx_origin_absent_from_code": not bool(re.search(r"\btx\s*\.\s*origin\b", masked)),
        "zero_address_guard_present": bool(re.search(r"address\s*\(\s*0\s*\)", masked)),
    }
    if not all(checks.values()):
        errors.append("expected_access_control_invariant_not_observed")

    conclusion = "SOURCE_PATTERN_MATCHED" if not errors else "INCONCLUSIVE"
    return {
        "schema_version": SCHEMA_VERSION,
        "repository": PINNED_REPOSITORY,
        "source_commit": source_commit,
        "source_path": source_path,
        "source_git_blob_sha1": actual_blob,
        "source_sha256": digest,
        "source_bytes": len(source_bytes),
        "checks": checks,
        "conclusion": conclusion,
        "errors": errors,
        "finding": False,
        "vulnerability_confirmed": False,
        "deployed_contract_verified": False,
        "historical_runtime_reproduced": False,
        "source_executed": False,
        "network_access_used": False,
        "interpretation": (
            "A match confirms only that the pinned upstream source contains the "
            "listed source-level patterns. It does not establish deployed bytecode "
            "identity, runtime behavior, or vulnerability/exploitability."
        ),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="local source file; never executed")
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
            source = raw.decode("utf-8")
            result = inspect_source(
                source, source_commit=args.commit, source_path=args.path,
                expected_git_blob_sha1=args.expected_git_blob_sha1,
            )
    except (OSError, UnicodeDecodeError) as exc:
        result = {
            "schema_version": SCHEMA_VERSION,
            "conclusion": "INCONCLUSIVE",
            "errors": [f"source_read_failed:{type(exc).__name__}"],
            "finding": False,
            "vulnerability_confirmed": False,
            "source_executed": False,
        }
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("conclusion") == "SOURCE_PATTERN_MATCHED" else 2


if __name__ == "__main__":
    sys.exit(main())
