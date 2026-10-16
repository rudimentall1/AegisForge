"""CLI for appending and verifying public AegisForge attestation registry snapshots."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

from shared.attestation import verify_attestation, canonical_json, sha256_hex
from shared.attestation_registry import (
    AttestationRegistryError,
    build_inclusion_proof,
    build_registry,
    checkpoint_for,
    entry_from_attestation,
    registry_sha256,
    verify_inclusion_proof,
    verify_registry,
    verify_registry_chain,
)

MAX_JSON_BYTES = 16 * 1024 * 1024


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _load_json(path: str | os.PathLike[str]) -> Any:
    raw = Path(path).read_bytes()
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("json_file_size_limit_exceeded")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("invalid_json_file") from exc


def _write_new_json(path: str | os.PathLike[str], payload: dict) -> None:
    target = Path(path)
    if target.is_symlink():
        raise ValueError("output_path_must_not_be_symlink")
    raw = (json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _load_trusted_keys(path):
    keys = _load_json(path)
    if not isinstance(keys, dict) or not all(
        isinstance(key_id, str) and isinstance(public_key, str)
        for key_id, public_key in keys.items()
    ):
        raise ValueError("trusted_keys_must_be_key_id_to_base64_public_key_object")
    return keys


def _add(args) -> int:
    attestation = _load_json(args.attestation)
    trusted = _load_trusted_keys(args.trusted_keys)
    verified = verify_attestation(attestation, trusted_keys=trusted)
    if verified.status != "VALID":
        print(json.dumps({
            "status": verified.status,
            "reason": verified.reason,
            "attestation_id": verified.attestation_id,
        }, sort_keys=True))
        return 2 if verified.status == "UNTRUSTED" else 1

    previous_checkpoint = None
    entries = []
    previous = None
    if args.previous_registry:
        previous = _load_json(args.previous_registry)
        verify_registry(previous)
        previous_checkpoint = checkpoint_for(previous)
        entries = [dict(entry) for entry in previous["entries"]]
    entry = entry_from_attestation(attestation)
    if any(item.get("attestation_id") == entry["attestation_id"] for item in entries):
        raise AttestationRegistryError("duplicate_attestation_id")
    entries.append(entry)
    registry = build_registry(entries, previous_checkpoint=previous_checkpoint)
    if previous is not None:
        verify_registry_chain(registry, previous)
    _write_new_json(args.output, registry)
    print(json.dumps({
        "status": "APPENDED",
        "size": registry["size"],
        "merkle_root": registry["merkle_root"],
        "registry_sha256": registry_sha256(registry),
        "output": str(args.output),
        "root_trust": "UNANCHORED",
    }, sort_keys=True))
    return 0


def _verify(args) -> int:
    registry = _load_json(args.registry)
    result = verify_registry(registry)
    output = dict(result)
    if args.previous_registry:
        previous = _load_json(args.previous_registry)
        output["chain"] = verify_registry_chain(registry, previous)
    print(json.dumps(output, sort_keys=True))
    return 0


def _proof(args) -> int:
    registry = _load_json(args.registry)
    proof = build_inclusion_proof(registry, args.attestation_id)
    if args.output:
        _write_new_json(args.output, proof)
        output = {
            "status": "PROOF_CREATED",
            "attestation_id": args.attestation_id,
            "merkle_root": proof["merkle_root"],
            "tree_size": proof["tree_size"],
            "output": args.output,
            "root_trust": "UNANCHORED",
        }
    else:
        output = proof
    print(json.dumps(output, sort_keys=True))
    return 0


def _verify_proof(args) -> int:
    proof = _load_json(args.proof)
    attestation = _load_json(args.attestation)
    trusted = _load_trusted_keys(args.trusted_keys)
    signature_result = verify_attestation(attestation, trusted_keys=trusted)
    if signature_result.status != "VALID":
        print(json.dumps({
            "status": signature_result.status,
            "reason": signature_result.reason,
            "attestation_id": signature_result.attestation_id,
        }, sort_keys=True))
        return 2 if signature_result.status == "UNTRUSTED" else 1
    result = verify_inclusion_proof(
        proof,
        expected_root=args.expected_root,
        expected_size=args.expected_size,
    )
    if (
        result["attestation_id"] != attestation.get("attestation_id")
        or proof["entry"].get("attestation_sha256") != sha256_hex(canonical_json(attestation))
    ):
        raise AttestationRegistryError("proof_does_not_bind_to_attestation")
    print(json.dumps({
        "status": "VALID",
        "signature": "VALID",
        "inclusion_proof": result,
        "root_trust": "EXTERNALLY_PINNED",
    }, sort_keys=True))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="aegisforge registry")
    sub = parser.add_subparsers(dest="command", required=True)
    add = sub.add_parser("add", help="append a trusted signed attestation to a new snapshot")
    add.add_argument("--attestation", required=True)
    add.add_argument("--trusted-keys", required=True)
    add.add_argument("--previous-registry")
    add.add_argument("--output", required=True)

    verify = sub.add_parser("verify", help="verify a registry snapshot and optional predecessor link")
    verify.add_argument("--registry", required=True)
    verify.add_argument("--previous-registry")

    proof = sub.add_parser("proof", help="create an inclusion proof for an attestation ID")
    proof.add_argument("--registry", required=True)
    proof.add_argument("--attestation-id", required=True)
    proof.add_argument("--output")

    verify_proof = sub.add_parser("verify-proof", help="verify inclusion plus the attestation signature")
    verify_proof.add_argument("--proof", required=True)
    verify_proof.add_argument("--attestation", required=True)
    verify_proof.add_argument("--trusted-keys", required=True)
    verify_proof.add_argument("--expected-root", required=True)
    verify_proof.add_argument("--expected-size", type=int)
    args = parser.parse_args(argv)

    try:
        if args.command == "add":
            return _add(args)
        if args.command == "verify":
            return _verify(args)
        if args.command == "proof":
            return _proof(args)
        return _verify_proof(args)
    except (OSError, ValueError, AttestationRegistryError) as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)[:200]}, sort_keys=True), file=sys.stderr)
        return 3
