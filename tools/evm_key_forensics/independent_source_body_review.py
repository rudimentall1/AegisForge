#!/usr/bin/env python3
"""Read-only cross-revision source check for Profanity Dispatcher.cpp.

This tool reads Git objects only. It does not build or execute Profanity and
does not import or call the AegisForge source checker.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

REVISIONS = {
    "pre_disclosure": {
        "commit": "0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6",
        "blob": "c9226fc02a52633a84664cbf3aaf2b4af8a59b25",
    },
    "post_disclosure_archive": {
        "commit": "186b9b27ab3e24a1899f648adcabcbf0e5f3131e",
        "blob": "884ced30ed6e55794ea5bda0451b52e81ddec1dd",
    },
}
FUNCTION_SIGNATURE = b"cl_ulong4 Dispatcher::Device::createSeed()"


class ReviewError(RuntimeError):
    pass


def git(repo: Path, *args: str) -> bytes:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode:
        detail = proc.stderr.decode("utf-8", errors="replace").strip()
        raise ReviewError(f"git {' '.join(args)} failed: {detail}")
    return proc.stdout


def _code_brace_positions(source: bytes, start: int):
    """Yield brace positions while ignoring C++ comments and quoted literals.

    This deliberately small lexer handles ordinary string/character literals,
    line comments, and block comments. It is not a complete C++ lexer or parser.
    """
    normal, line_comment, block_comment, string, character = range(5)
    state = normal
    escaped = False
    offset = start
    while offset < len(source):
        char = source[offset]
        nxt = source[offset + 1] if offset + 1 < len(source) else 0
        if state == normal:
            if char == ord("/") and nxt == ord("/"):
                state = line_comment
                offset += 2
                continue
            if char == ord("/") and nxt == ord("*"):
                state = block_comment
                offset += 2
                continue
            if char == ord('"'):
                state = string
            elif char == ord("'"):
                state = character
            elif char in (ord("{"), ord("}")):
                yield offset, char
        elif state == line_comment:
            if char in (ord("\\n"), ord("\\r")):
                state = normal
        elif state == block_comment:
            if char == ord("*") and nxt == ord("/"):
                state = normal
                offset += 2
                continue
        elif state in (string, character):
            if escaped:
                escaped = False
            elif char == ord("\\\\"):
                escaped = True
            elif (state == string and char == ord('"')) or (
                state == character and char == ord("'")
            ):
                state = normal
        offset += 1


def extract_function(source: bytes) -> bytes:
    start = source.find(FUNCTION_SIGNATURE)
    if start < 0:
        raise ReviewError("createSeed_signature_not_found")

    opening = None
    for offset, char in _code_brace_positions(source, start + len(FUNCTION_SIGNATURE)):
        if char == ord("{"):
            opening = offset
            break
    if opening is None:
        raise ReviewError("createSeed_opening_brace_not_found")

    depth = 0
    for offset, char in _code_brace_positions(source, opening):
        if char == ord("{"):
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                return source[opening : offset + 1]
    raise ReviewError("createSeed_unbalanced_braces")


def inspect_revision(repo: Path, name: str, spec: dict[str, str]) -> dict[str, object]:
    commit = spec["commit"]
    actual_commit = git(repo, "rev-parse", f"{commit}^{{commit}}").decode().strip()
    if actual_commit != commit:
        raise ReviewError(f"{name}: commit_identity_mismatch")

    actual_blob = git(repo, "rev-parse", f"{commit}:Dispatcher.cpp").decode().strip()
    if actual_blob != spec["blob"]:
        raise ReviewError(
            f"{name}: blob_id_mismatch expected={spec['blob']} actual={actual_blob}"
        )

    source = git(repo, "show", f"{commit}:Dispatcher.cpp")
    body = extract_function(source)
    return {
        "revision": name,
        "commit": actual_commit,
        "git_blob_sha1": actual_blob,
        "source_bytes": len(source),
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "function_body_bytes": len(body),
        "function_body_sha256": hashlib.sha256(body).hexdigest(),
    }, body


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Independently compare pinned Profanity createSeed source text."
    )
    parser.add_argument(
        "--repo",
        type=Path,
        required=True,
        help="Path to a local johguse/profanity Git checkout containing both commits.",
    )
    args = parser.parse_args()
    repo = args.repo.resolve()
    if not (repo / ".git").exists():
        print(json.dumps({"status": "ERROR", "error": "repo_is_not_git_checkout"}))
        return 2

    try:
        pre, pre_body = inspect_revision(repo, "pre_disclosure", REVISIONS["pre_disclosure"])
        post, post_body = inspect_revision(
            repo, "post_disclosure_archive", REVISIONS["post_disclosure_archive"]
        )
    except ReviewError as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}, indent=2))
        return 2

    same_body = pre_body == post_body
    report = {
        "status": "CHECKED",
        "method": "git_object_identity_plus_direct_function_text_comparison",
        "revisions": [pre, post],
        "same_function_body_bytes": same_body,
        "limitations": [
            "This is source-text comparison, not a human independent audit.",
            "It does not build or execute Profanity.",
            "It does not establish source-to-binary provenance or remediation.",
            "It does not prove entropy quality, exploitability, or wallet exposure.",
            "Extraction ignores ordinary C++ comments and quoted literals but is not a complete C++ lexer or parser.",
        ],
        "conclusion": "INCONCLUSIVE",
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if same_body else 1


if __name__ == "__main__":
    sys.exit(main())
