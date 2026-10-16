"""CLI for creating and verifying portable AegisForge Ed25519 attestations.

Tier 1 checks the envelope and canonical identity without trusting the signer.
Tier 2 verifies the Ed25519 signature against an explicitly trusted public key.
Tier 3 also binds the attestation to an expected case digest and verifies artifact
paths, sizes, and SHA-256 digests. Service requests are restricted to loopback HTTP.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared.attestation_signer_client import SignerClientError, request_attestation
from shared.attestation_workflow import WORKFLOW_VERDICTS, run_attestation_workflow
from shared.attestation import (
    ALLOWED_VERDICTS,
    SCHEMA_VERSION,
    SIGNATURE_ALGORITHM,
    AttestationError,
    canonical_json,
    sha256_hex,
    sign_attestation,
    verify_attestation,
)

MAX_JSON_BYTES = 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _reject_duplicate_json_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _load_json(path: str | os.PathLike[str]) -> Any:
    file_path = Path(path)
    raw = file_path.read_bytes()
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("json_file_size_limit_exceeded")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"nonstandard_json_constant:{value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("invalid_json_file") from exc


def _write_new_file(path: str | os.PathLike[str], content: bytes, mode: int) -> None:
    target = Path(path)
    if target.is_symlink():
        raise ValueError("output_path_must_not_be_symlink")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(str(target), flags, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _read_private_key(path: str | os.PathLike[str]) -> bytes:
    target = Path(path)
    if target.is_symlink() or not target.is_file():
        raise ValueError("private_key_path_must_be_regular_file")
    metadata = target.stat()
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError("private_key_permissions_too_open")
    raw = target.read_bytes()
    if len(raw) != 32:
        raise ValueError("private_key_must_be_32_raw_bytes")
    return raw


def _keygen(args) -> int:
    private_path = Path(args.private_key_file)
    public_path = Path(args.public_key_file)
    if private_path.resolve() == public_path.resolve():
        raise ValueError("private_and_public_key_paths_must_differ")
    if private_path.exists() or public_path.exists():
        raise ValueError("refusing_to_overwrite_existing_key_file")

    key = Ed25519PrivateKey.generate()
    private_raw = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_b64 = base64.b64encode(public_raw).decode("ascii")
    _write_new_file(private_path, private_raw, 0o600)
    _write_new_file(
        public_path,
        (json.dumps({args.key_id: public_b64}, sort_keys=True, indent=2) + "\n").encode("utf-8"),
        0o644,
    )
    print(json.dumps({
        "status": "KEY_CREATED",
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": args.key_id,
        "private_key_file": str(private_path),
        "public_trusted_keys_file": str(public_path),
        "private_key_material_printed": False,
    }, sort_keys=True))
    return 0


def _create_local_attestation(args) -> int:
    inputs = _load_json(args.input)
    if not isinstance(inputs, dict):
        raise ValueError("attestation_input_must_be_object")
    required = {
        "case_ref", "finding_ref", "reproduction", "verdict", "verdict_rationale"
    }
    if not required.issubset(inputs):
        raise ValueError("attestation_input_missing_required_fields")
    private_key = _read_private_key(args.private_key_file)
    attestation = sign_attestation(
        case_ref=inputs["case_ref"],
        finding_ref=inputs["finding_ref"],
        reproduction=inputs["reproduction"],
        verdict=inputs["verdict"],
        verdict_rationale=inputs["verdict_rationale"],
        private_key=private_key,
        key_id=args.key_id,
        organization=args.organization,
        issued_at=inputs.get("issued_at"),
    )
    serialized = json.dumps(attestation.to_dict(), sort_keys=True, indent=2) + "\n"
    _write_new_file(args.output, serialized.encode("utf-8"), 0o600)
    print(json.dumps({
        "status": "SIGNED",
        "attestation_id": attestation.to_dict()["attestation_id"],
        "schema_version": SCHEMA_VERSION,
        "output": str(args.output),
        "verdict": inputs["verdict"],
        "private_key_material_printed": False,
    }, sort_keys=True))
    return 0




def _request_attestation(args) -> int:
    inputs = _load_json(args.input)
    if not isinstance(inputs, dict):
        raise ValueError("attestation_input_must_be_object")
    required = {
        "case_ref", "finding_ref", "reproduction", "verdict", "verdict_rationale"
    }
    allowed = required | {"issued_at"}
    if not required.issubset(inputs):
        raise ValueError("attestation_input_missing_required_fields")
    if set(inputs) - allowed:
        raise ValueError("attestation_input_has_unexpected_fields")
    trusted = _load_json(args.trusted_keys)
    if not isinstance(trusted, dict) or not all(
        isinstance(key_id, str) and isinstance(public_key, str)
        for key_id, public_key in trusted.items()
    ):
        raise ValueError("trusted_keys_must_be_key_id_to_base64_public_key_object")
    attestation = request_attestation(inputs)
    verified = verify_attestation(attestation, trusted_keys=trusted)
    if verified.status != "VALID":
        print(json.dumps({
            "status": verified.status,
            "reason": verified.reason,
            "attestation_id": verified.attestation_id,
        }, sort_keys=True))
        return 2 if verified.status == "UNTRUSTED" else 1
    serialized = json.dumps(attestation, sort_keys=True, indent=2) + "\n"
    _write_new_file(args.output, serialized.encode("utf-8"), 0o600)
    print(json.dumps({
        "status": "SIGNED_BY_SERVICE",
        "attestation_id": attestation["attestation_id"],
        "schema_version": SCHEMA_VERSION,
        "output": str(args.output),
        "verdict": attestation["verdict"],
        "private_key_material_loaded_by_cli": False,
    }, sort_keys=True))
    return 0


def _tier1(payload: Any) -> dict[str, Any]:
    checks = {
        "schema_version": False,
        "canonical_identity": False,
        "verdict_allowed": False,
        "case_ref_shape": False,
        "finding_ref_shape": False,
        "reproduction_shape": False,
        "signer_shape": False,
        "signature_shape": False,
    }
    if not isinstance(payload, dict):
        return {"status": "INVALID", "reason": "invalid_payload", "checks": checks}
    if payload.get("schema_version") != SCHEMA_VERSION:
        return {"status": "INVALID", "reason": "unsupported_schema_version", "checks": checks}
    checks["schema_version"] = True
    if payload.get("verdict") not in ALLOWED_VERDICTS:
        return {"status": "INVALID", "reason": "verdict_not_allowed", "checks": checks}
    checks["verdict_allowed"] = True

    required_top = {
        "attestation_id", "case_ref", "finding_ref", "reproduction", "verdict",
        "verdict_rationale", "issued_at", "signer", "signature",
    }
    if not required_top.issubset(payload):
        return {"status": "INVALID", "reason": "required_fields_missing", "checks": checks}
    try:
        unsigned = {
            key: value for key, value in payload.items()
            if key not in {"attestation_id", "signature"}
        }
        expected_id = sha256_hex(canonical_json(unsigned))
    except AttestationError:
        return {"status": "INVALID", "reason": "noncanonical_payload", "checks": checks}
    if payload.get("attestation_id") != expected_id:
        return {"status": "TAMPERED", "reason": "attestation_id_mismatch", "checks": checks}
    checks["canonical_identity"] = True

    case = payload.get("case_ref")
    case_required = {
        "case_id", "case_digest", "target_repository", "target_commit",
        "scope_url", "scope_digest",
    }
    if (
        isinstance(case, dict)
        and case_required.issubset(case)
        and isinstance(case.get("case_id"), str) and case["case_id"]
        and isinstance(case.get("target_repository"), str) and case["target_repository"]
        and isinstance(case.get("target_commit"), str) and case["target_commit"]
        and SHA256_RE.fullmatch(str(case.get("case_digest", "")))
        and SHA256_RE.fullmatch(str(case.get("scope_digest", "")))
        and isinstance(case.get("scope_url"), str) and case["scope_url"].startswith("https://")
    ):
        checks["case_ref_shape"] = True

    finding = payload.get("finding_ref")
    finding_required = {
        "finding_id", "claim", "affected_component", "source_locations", "impact_path"
    }
    if (
        isinstance(finding, dict)
        and finding_required.issubset(finding)
        and isinstance(finding.get("finding_id"), str) and finding["finding_id"]
        and isinstance(finding.get("claim"), str)
        and isinstance(finding.get("affected_component"), str)
        and isinstance(finding.get("source_locations"), list)
        and isinstance(finding.get("impact_path"), str)
    ):
        checks["finding_ref_shape"] = True

    repro = payload.get("reproduction")
    repro_required = {
        "reproduction_contract_sha256", "commands", "environment", "network_access",
        "artifacts", "started_at", "completed_at", "exit_code",
    }
    if (
        isinstance(repro, dict)
        and repro_required.issubset(repro)
        and SHA256_RE.fullmatch(str(repro.get("reproduction_contract_sha256", "")))
        and isinstance(repro.get("commands"), list)
        and all(isinstance(command, list) and all(isinstance(arg, str) for arg in command)
                for command in repro["commands"])
        and isinstance(repro.get("environment"), dict)
        and isinstance(repro.get("network_access"), bool)
        and isinstance(repro.get("artifacts"), list)
        and isinstance(repro.get("started_at"), str) and repro["started_at"]
        and isinstance(repro.get("completed_at"), str) and repro["completed_at"]
        and isinstance(repro.get("exit_code"), int) and not isinstance(repro["exit_code"], bool)
    ):
        checks["reproduction_shape"] = True

    signer = payload.get("signer")
    signature = payload.get("signature")
    if (
        isinstance(signer, dict)
        and isinstance(signer.get("key_id"), str) and signer["key_id"]
        and isinstance(signer.get("organization"), str) and signer["organization"]
        and isinstance(signer.get("public_key"), str)
    ):
        try:
            public_raw = base64.b64decode(signer["public_key"], validate=True)
            checks["signer_shape"] = len(public_raw) == 32
        except (binascii.Error, ValueError):
            pass
    if isinstance(signature, dict) and signature.get("algorithm") == SIGNATURE_ALGORITHM:
        try:
            signature_raw = base64.b64decode(signature.get("value", ""), validate=True)
            checks["signature_shape"] = len(signature_raw) == 64
        except (binascii.Error, ValueError):
            pass

    if not all(checks.values()):
        return {"status": "INVALID", "reason": "tier1_structure_check_failed", "checks": checks}
    return {
        "status": "STRUCTURE_VALID",
        "reason": "tier1_structure_and_canonical_identity_valid; signer_not_verified",
        "attestation_id": payload["attestation_id"],
        "checks": checks,
    }


def _verify(args) -> int:
    payload = _load_json(args.attestation)
    tier1 = _tier1(payload)
    if tier1["status"] != "STRUCTURE_VALID":
        output = {"tier": 1, **tier1}
        print(json.dumps(output, sort_keys=True))
        return 1

    if args.level == "1":
        print(json.dumps({"tier": 1, **tier1}, sort_keys=True))
        return 0

    trusted = _load_json(args.trusted_keys)
    if not isinstance(trusted, dict) or not all(
        isinstance(key_id, str) and isinstance(value, str)
        for key_id, value in trusted.items()
    ):
        raise ValueError("trusted_keys_must_be_key_id_to_base64_public_key_object")

    kwargs = {"trusted_keys": trusted}
    if args.level == "3":
        if not args.expected_case_digest or not args.artifact_root:
            raise ValueError("tier3_requires_expected_case_digest_and_artifact_root")
        kwargs["expected_case_digest"] = args.expected_case_digest
        kwargs["artifact_root"] = args.artifact_root
    result = verify_attestation(payload, **kwargs)
    output = {"tier": int(args.level), **result.to_dict()}
    print(json.dumps(output, sort_keys=True))
    if result.status == "VALID":
        return 0
    if result.status == "UNTRUSTED":
        return 2
    return 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="aegisforge")
    sub = parser.add_subparsers(dest="command", required=True)
    attest = sub.add_parser("attest", help="create an Ed25519 evidence attestation")
    attest_sub = attest.add_subparsers(dest="attest_command", required=True)
    keygen = attest_sub.add_parser("keygen", help="create a local Ed25519 keypair")
    keygen.add_argument("--private-key-file", required=True)
    keygen.add_argument("--public-key-file", required=True)
    keygen.add_argument("--key-id", required=True)
    create = attest_sub.add_parser("create", help="request signing from the loopback signer; no private key file")
    create.add_argument("--input", required=True)
    create.add_argument("--trusted-keys", required=True)
    create.add_argument("--output", required=True)
    request = attest_sub.add_parser("request", help="alias for attest create")
    request.add_argument("--input", required=True)
    request.add_argument("--trusted-keys", required=True)
    request.add_argument("--output", required=True)
    create_local = attest_sub.add_parser("create-local", help="offline administrative signing from a local private key")
    create_local.add_argument("--input", required=True)
    create_local.add_argument("--private-key-file", required=True)
    create_local.add_argument("--key-id", required=True)
    create_local.add_argument("--organization", required=True)
    create_local.add_argument("--output", required=True)
    workflow = attest_sub.add_parser("workflow", help="human-gated source-evidence attestation and local Merkle registry workflow")
    workflow.add_argument("--evidence", required=True, help="validated offline Round-run JSON")
    workflow.add_argument("--verdict", choices=tuple(sorted(WORKFLOW_VERDICTS)), required=True)
    workflow.add_argument("--rationale", required=True, help="explicit human rationale for the selected verdict")
    workflow.add_argument("--trusted-keys", required=True)
    workflow.add_argument("--output-dir", required=True, help="existing directory; output files must not already exist")
    workflow.add_argument("--previous-registry")

    verify = sub.add_parser("verify", help="verify an attestation in three tiers")
    verify.add_argument("attestation")
    verify.add_argument("--level", choices=("1", "2", "3"), default="2")
    verify.add_argument("--trusted-keys", help="JSON object mapping key IDs to base64 public keys")
    verify.add_argument("--expected-case-digest")
    verify.add_argument("--artifact-root")
    args = parser.parse_args(argv)

    try:
        if args.command == "attest":
            if args.attest_command == "keygen":
                return _keygen(args)
            if args.attest_command in {"create", "request"}:
                return _request_attestation(args)
            if args.attest_command == "workflow":
                summary = run_attestation_workflow(
                    evidence_path=args.evidence,
                    verdict=args.verdict,
                    rationale=args.rationale,
                    trusted_keys_path=args.trusted_keys,
                    output_dir=args.output_dir,
                    previous_registry_path=args.previous_registry,
                )
                print(json.dumps(summary, sort_keys=True))
                return 0
            return _create_local_attestation(args)
        if args.level in {"2", "3"} and not args.trusted_keys:
            raise ValueError("tier2_and_tier3_require_trusted_keys")
        return _verify(args)
    except (OSError, ValueError, AttestationError, SignerClientError, binascii.Error) as exc:
        print(json.dumps({
            "status": "ERROR",
            "error": str(exc)[:240],
        }, sort_keys=True), file=sys.stderr)
        return 3
