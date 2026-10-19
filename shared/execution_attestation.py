"""Detached Ed25519 attestations for local experiment provenance.

A valid signature proves that a holder of the supplied private key signed the
claims. It does not by itself prove the runner was uncompromised or that the
claims describe truthful execution. The verifier requires an externally trusted
public key; the attestation never establishes its own trust.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ATTESTATION_SCHEMA_VERSION = "aegisforge-execution-attestation-v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_REQUIRED_CLAIMS = {
    "schema_version", "signer_id", "runner_id", "case_id", "round_id",
    "task_id", "target_repository", "target_commit", "record_sha256",
    "environment_sha256", "issued_at", "nonce",
}


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _valid_id(value: object) -> bool:
    return isinstance(value, str) and bool(_ID_RE.fullmatch(value))


def _validate_claims(claims: object) -> list[str]:
    if not isinstance(claims, dict) or set(claims) != _REQUIRED_CLAIMS:
        return ["attestation_claims_schema_invalid"]
    for field in ("signer_id", "runner_id", "case_id", "round_id", "task_id", "nonce"):
        if not _valid_id(claims.get(field)):
            return [f"attestation_{field}_invalid"]
    if claims.get("schema_version") != ATTESTATION_SCHEMA_VERSION:
        return ["attestation_schema_unsupported"]
    repository = claims.get("target_repository")
    if not isinstance(repository, str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository
    ):
        return ["attestation_target_repository_invalid"]
    if not isinstance(claims.get("target_commit"), str) or not _COMMIT_RE.fullmatch(
        claims["target_commit"]
    ):
        return ["attestation_target_commit_invalid"]
    for field in ("record_sha256", "environment_sha256"):
        value = claims.get(field)
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            return [f"attestation_{field}_invalid"]
    issued_at = claims.get("issued_at")
    if not isinstance(issued_at, str) or not issued_at.strip() or len(issued_at) > 64:
        return ["attestation_issued_at_invalid"]
    return []


def create_execution_attestation(
    *,
    record: Mapping,
    signer_id: str,
    runner_id: str,
    environment_sha256: str,
    issued_at: str,
    nonce: str,
    private_key_bytes: bytes,
) -> dict:
    """Sign claims that bind a verified experiment record to runner metadata.

    The caller is responsible for authenticating the runner before signing.
    This function does not execute or independently validate a process.
    """
    if not isinstance(record, Mapping):
        raise ValueError("attestation_record_required")
    if not isinstance(private_key_bytes, bytes) or len(private_key_bytes) != 32:
        raise ValueError("attestation_ed25519_private_key_must_be_32_bytes")
    record_bytes = _canonical_json(dict(record))
    claims = {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "signer_id": signer_id,
        "runner_id": runner_id,
        "case_id": record.get("case_id"),
        "round_id": record.get("round_id"),
        "task_id": record.get("task_id"),
        "target_repository": record.get("target_repository"),
        "target_commit": record.get("target_commit"),
        "record_sha256": hashlib.sha256(record_bytes).hexdigest(),
        "environment_sha256": environment_sha256,
        "issued_at": issued_at,
        "nonce": nonce,
    }
    errors = _validate_claims(claims)
    if errors:
        raise ValueError(errors[0])
    signature = Ed25519PrivateKey.from_private_bytes(private_key_bytes).sign(
        _canonical_json(claims)
    )
    return {
        "claims": claims,
        "signature_ed25519": signature.hex(),
        "authenticity": "SIGNED_CLAIMS_ONLY",
    }


def verify_execution_attestation(
    attestation: object,
    *,
    trusted_public_key_bytes: bytes,
    expected_signer_id: str,
    expected_record: Mapping | None = None,
) -> dict:
    """Verify a detached signature against a caller-supplied trusted public key."""
    base = {
        "status": "FAIL",
        "attestation_verified": False,
        "execution_truth_established": False,
        "runner_compromise_ruled_out": False,
        "errors": [],
    }
    if not isinstance(trusted_public_key_bytes, bytes) or len(trusted_public_key_bytes) != 32:
        return {**base, "errors": ["trusted_ed25519_public_key_must_be_32_bytes"]}
    if not _valid_id(expected_signer_id):
        return {**base, "errors": ["expected_signer_id_invalid"]}
    if not isinstance(attestation, dict) or set(attestation) != {
        "claims", "signature_ed25519", "authenticity"
    }:
        return {**base, "errors": ["attestation_envelope_invalid"]}
    if attestation.get("authenticity") != "SIGNED_CLAIMS_ONLY":
        return {**base, "errors": ["attestation_authenticity_label_invalid"]}
    claims = attestation.get("claims")
    errors = _validate_claims(claims)
    if errors:
        return {**base, "errors": errors}
    if claims["signer_id"] != expected_signer_id:
        return {**base, "errors": ["attestation_signer_identity_mismatch"]}
    signature_hex = attestation.get("signature_ed25519")
    if not isinstance(signature_hex, str) or not re.fullmatch(r"[0-9a-f]{128}", signature_hex):
        return {**base, "errors": ["attestation_signature_encoding_invalid"]}
    if expected_record is not None:
        if not isinstance(expected_record, Mapping):
            return {**base, "errors": ["expected_record_invalid"]}
        expected_digest = hashlib.sha256(_canonical_json(dict(expected_record))).hexdigest()
        if claims["record_sha256"] != expected_digest:
            return {**base, "errors": ["attestation_record_digest_mismatch"]}
        for field in (
            "case_id", "round_id", "task_id", "target_repository", "target_commit"
        ):
            if claims[field] != expected_record.get(field):
                return {**base, "errors": ["attestation_record_identity_mismatch"]}
    try:
        Ed25519PublicKey.from_public_bytes(trusted_public_key_bytes).verify(
            bytes.fromhex(signature_hex), _canonical_json(claims)
        )
    except (InvalidSignature, ValueError):
        return {**base, "errors": ["attestation_signature_invalid"]}
    return {
        **base,
        "status": "PASS",
        "attestation_verified": True,
        "execution_truth_established": False,
        "runner_compromise_ruled_out": False,
        "signer_id": claims["signer_id"],
        "runner_id": claims["runner_id"],
        "record_sha256": claims["record_sha256"],
        "environment_sha256": claims["environment_sha256"],
        "case_id": claims["case_id"],
        "round_id": claims["round_id"],
        "task_id": claims["task_id"],
        "target_repository": claims["target_repository"],
        "target_commit": claims["target_commit"],
        "errors": [],
        "limitations": [
            "Signature verification proves the claims were signed by the key corresponding to the externally trusted public key.",
            "It does not prove the runner executed the command truthfully or was uncompromised.",
            "Trust-store management, key rotation, revocation, freshness policy, and replay prevention remain caller responsibilities.",
        ],
    }
