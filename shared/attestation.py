"""Portable, offline-verifiable Ed25519 attestations for AegisForge.

The module deliberately performs no network I/O and never logs key material or
artifact contents. An attestation records a bounded reproduction result; it is
not a declaration that a vulnerability is confirmed.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


SCHEMA_VERSION = "aegisforge-attestation-v1"
SIGNATURE_ALGORITHM = "Ed25519"
ALLOWED_VERDICTS = frozenset(
    {"REPRODUCED", "NOT_REPRODUCED", "INCONCLUSIVE", "OUT_OF_SCOPE"}
)
MAX_RATIONALE_BYTES = 8192
HEX_SHA256_LENGTH = 64


class AttestationError(ValueError):
    """Raised when an attestation cannot safely be constructed or inspected."""


@dataclass(frozen=True)
class Attestation:
    """Typed wrapper around the JSON-compatible attestation payload."""

    payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return json.loads(canonical_json(self.payload))


@dataclass(frozen=True)
class VerificationResult:
    status: str
    reason: str
    attestation_id: str | None
    checks: dict[str, bool]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def canonical_json(value: Any) -> str:
    """Serialize JSON deterministically using the attestation wire format."""
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
    except (TypeError, ValueError) as exc:
        raise AttestationError("value_not_canonical_json_serializable") from exc


def sha256_hex(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    if not isinstance(value, bytes):
        raise AttestationError("sha256_input_must_be_str_or_bytes")
    return hashlib.sha256(value).hexdigest()


def _is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != HEX_SHA256_LENGTH:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _decode_public_key(value: Any) -> bytes:
    if not isinstance(value, str):
        raise AttestationError("invalid_public_key_encoding")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AttestationError("invalid_public_key_encoding") from exc
    if len(raw) != 32:
        raise AttestationError("invalid_public_key_length")
    return raw


def _trusted_key_bytes(value: Any) -> bytes:
    if isinstance(value, Ed25519PublicKey):
        return value.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        try:
            raw = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise AttestationError("invalid_trusted_key_encoding") from exc
    else:
        raise AttestationError("invalid_trusted_key_type")
    if len(raw) != 32:
        raise AttestationError("invalid_trusted_key_length")
    return raw


def _private_key(value: Any) -> Ed25519PrivateKey:
    if isinstance(value, Ed25519PrivateKey):
        return value
    if isinstance(value, bytes) and len(value) == 32:
        try:
            return Ed25519PrivateKey.from_private_bytes(value)
        except ValueError as exc:
            raise AttestationError("invalid_private_key") from exc
    raise AttestationError("private_key_must_be_ed25519_key_or_32_bytes")


def _public_key_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def _unsigned_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items()
            if key not in {"attestation_id", "signature"}}


def _signed_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "signature"}


def _validate_object(value: Any, required: set[str], error: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not required.issubset(value):
        raise AttestationError(error)
    return value


def _validate_construction(
    case_ref: Any,
    finding_ref: Any,
    reproduction: Any,
    verdict: Any,
    verdict_rationale: Any,
    key_id: Any,
    organization: Any,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    case = _validate_object(
        case_ref,
        {"case_id", "case_digest", "target_repository", "target_commit",
         "scope_url", "scope_digest"},
        "invalid_case_ref",
    )
    finding = _validate_object(
        finding_ref,
        {"finding_id", "claim", "affected_component", "source_locations",
         "impact_path"},
        "invalid_finding_ref",
    )
    repro = _validate_object(
        reproduction,
        {"reproduction_contract_sha256", "commands", "environment",
         "network_access", "artifacts", "started_at", "completed_at", "exit_code"},
        "invalid_reproduction",
    )
    if not _is_sha256(case["case_digest"]) or not _is_sha256(case["scope_digest"]):
        raise AttestationError("invalid_case_digest")
    if not _is_sha256(repro["reproduction_contract_sha256"]):
        raise AttestationError("invalid_reproduction_contract_digest")
    if not isinstance(finding["source_locations"], list):
        raise AttestationError("invalid_source_locations")
    if not isinstance(repro["commands"], list) or not all(
        isinstance(command, list) and all(isinstance(arg, str) for arg in command)
        for command in repro["commands"]
    ):
        raise AttestationError("invalid_reproduction_commands")
    if not isinstance(repro["environment"], dict):
        raise AttestationError("invalid_reproduction_environment")
    if not isinstance(repro["artifacts"], list):
        raise AttestationError("invalid_reproduction_artifacts")
    if not isinstance(repro["network_access"], bool):
        raise AttestationError("invalid_network_access")
    if not isinstance(repro["exit_code"], int) or isinstance(repro["exit_code"], bool):
        raise AttestationError("invalid_exit_code")
    if not isinstance(verdict, str) or verdict not in ALLOWED_VERDICTS:
        raise AttestationError("verdict_not_allowed")
    if not isinstance(verdict_rationale, str):
        raise AttestationError("invalid_verdict_rationale")
    if len(verdict_rationale.encode("utf-8")) > MAX_RATIONALE_BYTES:
        raise AttestationError("verdict_rationale_too_long")
    if not isinstance(key_id, str) or not key_id:
        raise AttestationError("invalid_key_id")
    if not isinstance(organization, str) or not organization:
        raise AttestationError("invalid_organization")
    return case, finding, repro


def sign_attestation(
    *,
    case_ref: dict[str, Any],
    finding_ref: dict[str, Any],
    reproduction: dict[str, Any],
    verdict: str,
    verdict_rationale: str,
    private_key: Ed25519PrivateKey | bytes,
    key_id: str,
    organization: str,
    issued_at: str | None = None,
) -> Attestation:
    case, finding, repro = _validate_construction(
        case_ref, finding_ref, reproduction, verdict, verdict_rationale,
        key_id, organization,
    )
    key = _private_key(private_key)
    timestamp = issued_at or datetime.now(timezone.utc).isoformat()
    if not isinstance(timestamp, str) or not timestamp:
        raise AttestationError("invalid_issued_at")
    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AttestationError("invalid_issued_at") from exc

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "case_ref": case,
        "finding_ref": finding,
        "reproduction": repro,
        "verdict": verdict,
        "verdict_rationale": verdict_rationale,
        "issued_at": timestamp,
        "signer": {
            "key_id": key_id,
            "public_key": _public_key_b64(key),
            "organization": organization,
        },
    }
    payload["attestation_id"] = sha256_hex(canonical_json(_unsigned_payload(payload)))
    signature = key.sign(canonical_json(_signed_payload(payload)).encode("utf-8"))
    payload["signature"] = {
        "algorithm": SIGNATURE_ALGORITHM,
        "value": base64.b64encode(signature).decode("ascii"),
    }
    return Attestation(payload=payload)


def _result(status: str, reason: str, attestation_id: Any, checks: dict[str, bool]):
    return VerificationResult(
        status=status,
        reason=reason,
        attestation_id=attestation_id if isinstance(attestation_id, str) else None,
        checks=checks,
    )


def _artifact_path(root: Path, relative: Any) -> Path:
    if not isinstance(relative, str) or not relative:
        raise AttestationError("invalid_artifact_path")
    candidate_path = Path(relative)
    if candidate_path.is_absolute():
        raise AttestationError("artifact_path_outside_root")
    root_resolved = root.resolve()
    candidate = (root_resolved / candidate_path).resolve()
    try:
        candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise AttestationError("artifact_path_outside_root") from exc
    return candidate


def _verify_artifacts(payload: dict[str, Any], artifact_root: str | os.PathLike[str]):
    root = Path(artifact_root)
    if not root.exists() or not root.is_dir():
        return "INVALID", "artifact_root_missing", False, False
    artifacts = payload.get("reproduction", {}).get("artifacts")
    if not isinstance(artifacts, list):
        return "INVALID", "invalid_reproduction_artifacts", False, False
    paths_ok = True
    content_ok = True
    for artifact in artifacts:
        if not isinstance(artifact, dict) or not {
            "path", "sha256", "size_bytes"
        }.issubset(artifact):
            return "INVALID", "invalid_artifact_entry", paths_ok, False
        try:
            path = _artifact_path(root, artifact["path"])
        except AttestationError:
            raise
        if not path.is_file():
            return "INVALID", "artifact_missing", paths_ok, False
        digest = hashlib.sha256()
        size = 0
        try:
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
                    size += len(chunk)
        except OSError:
            return "INVALID", "artifact_unreadable", paths_ok, False
        if not _is_sha256(artifact["sha256"]):
            return "INVALID", "invalid_artifact_digest", paths_ok, False
        if digest.hexdigest() != artifact["sha256"] or size != artifact["size_bytes"]:
            content_ok = False
    if not content_ok:
        return "TAMPERED", "artifact_mismatch", paths_ok, False
    return "VALID", "ok", paths_ok, content_ok


def verify_attestation(
    payload: dict[str, Any] | Attestation,
    *,
    trusted_keys: Mapping[str, Any],
    expected_case_digest: str | None = None,
    artifact_root: str | os.PathLike[str] | None = None,
) -> VerificationResult:
    """Verify schema, identity, trusted signer and signature without network I/O."""
    if isinstance(payload, Attestation):
        payload = payload.to_dict()
    checks = {
        "schema_version": False,
        "attestation_id": False,
        "signature_algorithm": False,
        "trusted_key": False,
        "public_key_matches": False,
        "signature_valid": False,
        "verdict_allowed": False,
        "artifacts_path_safe": True,
        "artifacts_valid": True,
        "case_digest_matches": True,
    }
    if not isinstance(payload, dict):
        return _result("INVALID", "invalid_payload", None, checks)
    attestation_id = payload.get("attestation_id")
    if payload.get("schema_version") != SCHEMA_VERSION:
        return _result("INVALID", "unsupported_schema_version", attestation_id, checks)
    checks["schema_version"] = True

    verdict = payload.get("verdict")
    if not isinstance(verdict, str) or verdict not in ALLOWED_VERDICTS:
        return _result("INVALID", "verdict_not_allowed", attestation_id, checks)
    checks["verdict_allowed"] = True

    try:
        expected_id = sha256_hex(canonical_json(_unsigned_payload(payload)))
    except AttestationError:
        return _result("INVALID", "invalid_unsigned_payload", attestation_id, checks)
    if not isinstance(attestation_id, str) or attestation_id != expected_id:
        return _result("TAMPERED", "attestation_id_mismatch", attestation_id, checks)
    checks["attestation_id"] = True

    signer = payload.get("signer")
    signature = payload.get("signature")
    if not isinstance(signer, dict) or not isinstance(signature, dict):
        return _result("INVALID", "signer_or_signature_missing", attestation_id, checks)
    if signature.get("algorithm") != SIGNATURE_ALGORITHM:
        return _result("INVALID", "signature_algorithm_not_allowed", attestation_id, checks)
    checks["signature_algorithm"] = True
    key_id = signer.get("key_id")
    if not isinstance(key_id, str) or key_id not in trusted_keys:
        return _result("UNTRUSTED", "untrusted_key", attestation_id, checks)
    checks["trusted_key"] = True
    try:
        advertised_key = _decode_public_key(signer.get("public_key"))
        trusted_key = _trusted_key_bytes(trusted_keys[key_id])
    except AttestationError:
        return _result("INVALID", "invalid_public_key", attestation_id, checks)
    if advertised_key != trusted_key:
        return _result("UNTRUSTED", "public_key_mismatch", attestation_id, checks)
    checks["public_key_matches"] = True

    try:
        signature_bytes = base64.b64decode(signature.get("value", ""), validate=True)
        public_key = Ed25519PublicKey.from_public_bytes(trusted_key)
        public_key.verify(
            signature_bytes, canonical_json(_signed_payload(payload)).encode("utf-8")
        )
    except (InvalidSignature, ValueError, binascii.Error, TypeError):
        return _result("TAMPERED", "signature_invalid", attestation_id, checks)
    checks["signature_valid"] = True

    case_ref = payload.get("case_ref")
    if not isinstance(case_ref, dict):
        return _result("INVALID", "invalid_case_ref", attestation_id, checks)
    if expected_case_digest is not None:
        if not _is_sha256(expected_case_digest) or case_ref.get("case_digest") != expected_case_digest:
            checks["case_digest_matches"] = False
            return _result("INVALID", "case_digest_mismatch", attestation_id, checks)

    if artifact_root is not None:
        try:
            artifact_status, artifact_reason, paths_ok, artifacts_ok = _verify_artifacts(
                payload, artifact_root
            )
        except AttestationError as exc:
            checks["artifacts_path_safe"] = False
            return _result("INVALID", str(exc), attestation_id, checks)
        checks["artifacts_path_safe"] = paths_ok
        checks["artifacts_valid"] = artifacts_ok
        if artifact_status != "VALID":
            return _result(artifact_status, artifact_reason, attestation_id, checks)

    return _result("VALID", "ok", attestation_id, checks)
