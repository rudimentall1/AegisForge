"""Canonical, portable receipts for bounded lab executions.

This module defines serialization and signature verification only. A valid
signature authenticates a statement from a configured key; it does not prove
that the runner was isolated or uncompromised.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class LabExecutionReceiptError(ValueError):
    """Raised when a lab receipt is malformed or cannot be verified."""


def canonical_json(payload: dict) -> bytes:
    """Return deterministic UTF-8 JSON bytes for a JSON object."""
    if not isinstance(payload, dict):
        raise LabExecutionReceiptError("receipt_object_required")
    try:
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise LabExecutionReceiptError("receipt_not_canonicalizable") from exc
    return encoded.encode("utf-8")


def build_receipt(
    *,
    run_id: str,
    experiment_id: str,
    inputs: dict,
    execution: dict,
    artifacts: dict | None = None,
) -> dict:
    """Build a canonical receipt envelope from explicit run inputs and observations.

    Callers must supply already-computed SHA-256 digests for artifact bytes.
    This function validates shape; it does not execute or attest the experiment.
    """
    if not isinstance(run_id, str) or not run_id.strip():
        raise LabExecutionReceiptError("run_id_required")
    if not isinstance(experiment_id, str) or not experiment_id.strip():
        raise LabExecutionReceiptError("experiment_id_required")
    if not isinstance(inputs, dict) or not isinstance(execution, dict):
        raise LabExecutionReceiptError("inputs_and_execution_objects_required")
    if artifacts is not None and not isinstance(artifacts, dict):
        raise LabExecutionReceiptError("artifacts_object_required")
    receipt = {
        "schema_version": 1,
        "receipt_type": "aegisforge.lab_execution",
        "run_id": run_id,
        "experiment_id": experiment_id,
        "inputs": inputs,
        "execution": execution,
        "artifacts": artifacts or {},
    }
    # Fail early for unserializable data and non-finite floats.
    canonical_json(receipt)
    return receipt


def receipt_sha256(receipt: dict) -> str:
    return hashlib.sha256(canonical_json(receipt)).hexdigest()


def sign_receipt(
    receipt: dict,
    *,
    private_key: Ed25519PrivateKey,
    key_id: str,
) -> dict:
    """Sign canonical receipt bytes with a caller-managed Ed25519 private key."""
    if not isinstance(private_key, Ed25519PrivateKey):
        raise LabExecutionReceiptError("ed25519_private_key_required")
    if not isinstance(key_id, str) or not key_id.strip():
        raise LabExecutionReceiptError("key_id_required")
    if receipt.get("schema_version") != 1 or receipt.get("receipt_type") != "aegisforge.lab_execution":
        raise LabExecutionReceiptError("unsupported_receipt_schema")
    payload_bytes = canonical_json(receipt)
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "schema_version": 1,
        "algorithm": "Ed25519",
        "key_id": key_id,
        "receipt": receipt,
        "receipt_sha256": hashlib.sha256(payload_bytes).hexdigest(),
        "signer_public_key_sha256": hashlib.sha256(public_bytes).hexdigest(),
        "signature": base64.b64encode(private_key.sign(payload_bytes)).decode("ascii"),
    }


def verify_signed_receipt(
    envelope: dict,
    *,
    trusted_public_keys: Mapping[str, bytes],
) -> dict:
    """Verify signature and digest against an explicit key-id -> raw public-key map."""
    if not isinstance(envelope, dict):
        raise LabExecutionReceiptError("signed_receipt_object_required")
    if envelope.get("schema_version") != 1 or envelope.get("algorithm") != "Ed25519":
        raise LabExecutionReceiptError("unsupported_signed_receipt_schema")
    key_id = envelope.get("key_id")
    if not isinstance(key_id, str) or key_id not in trusted_public_keys:
        raise LabExecutionReceiptError("untrusted_runner_key")
    receipt = envelope.get("receipt")
    if not isinstance(receipt, dict):
        raise LabExecutionReceiptError("receipt_object_required")
    if receipt.get("schema_version") != 1 or receipt.get("receipt_type") != "aegisforge.lab_execution":
        raise LabExecutionReceiptError("unsupported_receipt_schema")
    payload_bytes = canonical_json(receipt)
    digest = hashlib.sha256(payload_bytes).hexdigest()
    if digest != envelope.get("receipt_sha256"):
        raise LabExecutionReceiptError("receipt_digest_mismatch")
    public_bytes = trusted_public_keys[key_id]
    if not isinstance(public_bytes, bytes):
        raise LabExecutionReceiptError("trusted_public_key_must_be_raw_bytes")
    if hashlib.sha256(public_bytes).hexdigest() != envelope.get("signer_public_key_sha256"):
        raise LabExecutionReceiptError("signer_key_fingerprint_mismatch")
    try:
        signature = base64.b64decode(envelope.get("signature", ""), validate=True)
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, payload_bytes)
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise LabExecutionReceiptError("receipt_signature_invalid") from exc
    return {
        "valid": True,
        "key_id": key_id,
        "receipt_sha256": digest,
        "run_id": receipt["run_id"],
        "experiment_id": receipt["experiment_id"],
    }
