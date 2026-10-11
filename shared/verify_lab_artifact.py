"""Offline verification for exported AegisForge lab artifacts.

This verifies internal consistency and optional Ed25519 trust. It cannot prove
that the runner was isolated, honest, or that a historical vulnerability exists.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

from shared.lab_execution_receipt import (
    LabExecutionReceiptError,
    receipt_sha256,
    verify_signed_receipt,
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def verify_lab_artifact(experiment: dict, trusted_public_keys: dict[str, bytes] | None = None) -> dict:
    """Verify an exported single experiment without contacting the issuer."""
    trusted_public_keys = trusted_public_keys or {}
    if not isinstance(experiment, dict):
        raise ValueError("experiment_object_required")

    receipt = experiment.get("execution_receipt")
    reported_digest = experiment.get("execution_receipt_sha256")
    record = experiment.get("execution_record")
    checks = {
        "receipt_present": isinstance(receipt, dict),
        "record_present": isinstance(record, dict),
    }
    try:
        calculated_digest = receipt_sha256(receipt)
        checks["receipt_digest_matches"] = calculated_digest == reported_digest
    except (LabExecutionReceiptError, TypeError, ValueError):
        calculated_digest = None
        checks["receipt_digest_matches"] = False

    inputs = receipt.get("inputs") if isinstance(receipt, dict) else None
    execution = receipt.get("execution") if isinstance(receipt, dict) else None
    artifacts = receipt.get("artifacts") if isinstance(receipt, dict) else None
    command = record.get("command") if isinstance(record, dict) else None
    stdout = record.get("stdout") if isinstance(record, dict) else None
    stderr = record.get("stderr") if isinstance(record, dict) else None

    checks["command_digest_matches"] = (
        isinstance(record, dict)
        and isinstance(command, list)
        and record.get("command_sha256")
        == _sha256(json.dumps(command, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    )
    checks["stdout_digest_matches"] = (
        isinstance(record, dict) and isinstance(stdout, str)
        and record.get("stdout_sha256") == _sha256(stdout.encode("utf-8"))
    )
    checks["stderr_digest_matches"] = (
        isinstance(record, dict) and isinstance(stderr, str)
        and record.get("stderr_sha256") == _sha256(stderr.encode("utf-8"))
    )
    checks["command_matches_receipt"] = (
        isinstance(inputs, dict) and isinstance(record, dict)
        and inputs.get("argv") == command
        and inputs.get("script_source_sha256") == record.get("script_source_sha256")
        and isinstance(artifacts, dict)
        and artifacts.get("script_source_sha256") == record.get("script_source_sha256")
    )

    result_payload_digest = None
    if isinstance(stdout, str):
        try:
            result_payload_digest = _sha256(_canonical_json(json.loads(stdout)))
        except (TypeError, ValueError):
            pass
    checks["result_payload_digest_matches"] = (
        isinstance(artifacts, dict)
        and result_payload_digest is not None
        and artifacts.get("result_payload_sha256") == result_payload_digest
    )
    checks["execution_matches_receipt"] = (
        isinstance(execution, dict) and isinstance(record, dict)
        and receipt.get("experiment_id") == experiment.get("experiment_id")
        and execution.get("exit_code") == record.get("exit_code")
        and execution.get("timed_out") == record.get("timed_out")
        and execution.get("test_passed") == record.get("test_passed")
        and execution.get("stdout_sha256") == record.get("stdout_sha256")
        and execution.get("stderr_sha256") == record.get("stderr_sha256")
    )

    integrity_verified = all(checks.values())
    successful_execution = (
        integrity_verified
        and record.get("timed_out") is False
        and record.get("exit_code") == 0
        and record.get("test_passed") is True
    ) if isinstance(record, dict) else False

    envelope = experiment.get("execution_receipt_envelope")
    signature_verified = False
    signature_error = None
    signer_key_id = None
    if isinstance(envelope, dict):
        try:
            result = verify_signed_receipt(envelope, trusted_public_keys=trusted_public_keys)
            signature_verified = (
                result.get("valid") is True
                and envelope.get("receipt") == receipt
                and result.get("receipt_sha256") == reported_digest
            )
            if signature_verified:
                signer_key_id = result.get("key_id")
        except (LabExecutionReceiptError, TypeError, ValueError) as exc:
            signature_error = str(exc)

    authenticity = (
        "SIGNED_AND_TRUSTED" if signature_verified else
        "SIGNATURE_INVALID_OR_UNTRUSTED" if isinstance(envelope, dict) else
        "UNTRUSTED_UNSIGNED"
    )
    return {
        "schema_version": 1,
        "integrity_verified": integrity_verified,
        "successful_execution": successful_execution,
        "authenticity": authenticity,
        "signature_verified_against_trusted_key": signature_verified,
        "signer_key_id": signer_key_id,
        "signature_error": signature_error,
        "receipt_sha256": calculated_digest,
        "checks": checks,
        "limitations": [
            "A matching digest detects changes but does not authenticate an unsigned artifact.",
            "A trusted signature authenticates the signed statement, not the honesty or isolation of the runner.",
            "This artifact alone does not prove a historical vulnerability was reproduced.",
        ],
    }


def _load_trusted_key(value: str) -> tuple[str, bytes]:
    if "=" not in value:
        raise ValueError("trusted_key_must_be_KEY_ID=PATH")
    key_id, path = value.split("=", 1)
    if not key_id.strip() or not path.strip():
        raise ValueError("trusted_key_must_be_KEY_ID=PATH")
    raw = Path(path).read_bytes()
    # Accept raw 32-byte Ed25519 public keys or base64-encoded raw keys.
    if len(raw) != 32:
        try:
            raw = base64.b64decode(raw.strip(), validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("trusted_ed25519_public_key_must_be_32_bytes_or_base64") from exc
    if len(raw) != 32:
        raise ValueError("trusted_ed25519_public_key_must_be_32_bytes")
    return key_id, raw


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Verify an exported AegisForge lab experiment offline.")
    parser.add_argument("artifact", help="Path to JSON containing one lab experiment")
    parser.add_argument(
        "--trusted-key", action="append", default=[], metavar="KEY_ID=PATH",
        help="Trusted Ed25519 public key file; may be repeated",
    )
    args = parser.parse_args(argv)
    try:
        artifact = json.loads(Path(args.artifact).read_text(encoding="utf-8"))
        if isinstance(artifact, dict) and isinstance(artifact.get("lab_experiments"), list):
            experiments = artifact["lab_experiments"]
            if len(experiments) != 1:
                raise ValueError("artifact_must_contain_exactly_one_lab_experiment")
            experiment = experiments[0]
        else:
            experiment = artifact
        trusted = {}
        for item in args.trusted_key:
            key_id, key_bytes = _load_trusted_key(item)
            if key_id in trusted:
                raise ValueError("duplicate_trusted_key_id")
            trusted[key_id] = key_bytes
        result = verify_lab_artifact(experiment, trusted)
        print(json.dumps(result, indent=2, sort_keys=True))
        if not result["integrity_verified"]:
            return 1
        if result["authenticity"] == "SIGNATURE_INVALID_OR_UNTRUSTED":
            return 2
        return 0
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({"error": str(exc), "integrity_verified": False}, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
