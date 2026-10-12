"""Signed checkpoints for an externally anchored replay-registry state.

This module verifies checkpoint statements. It does not persist a monotonic
high-water mark; callers must obtain that mark from storage outside the
registry's rollback domain and must fail closed if it is unavailable.
"""
from __future__ import annotations

import base64
import json
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA_VERSION = "evm-key-forensics-replay-checkpoint-v1"
_DOMAIN = b"OWNERA-AEGISFORGE-REPLAY-CHECKPOINT-V1\x00"
_FIELDS = {"schema_version", "provider_id", "sequence", "head_sha256", "key_id"}
_GENESIS = "0" * 64


class ReplayCheckpointError(ValueError):
    """Raised when a checkpoint is malformed, untrusted, or behind the anchor."""


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def sign_registry_checkpoint(
    *, provider_id: str, sequence: int, head_sha256: str, key_id: str,
    private_key: Ed25519PrivateKey,
) -> dict:
    """Create a checkpoint statement for an external trusted operator to sign."""
    if not isinstance(provider_id, str) or not provider_id.strip():
        raise ReplayCheckpointError("checkpoint_provider_id_invalid")
    if type(sequence) is not int or sequence < 0:
        raise ReplayCheckpointError("checkpoint_sequence_invalid")
    if not isinstance(head_sha256, str) or len(head_sha256) != 64 or any(c not in "0123456789abcdef" for c in head_sha256):
        raise ReplayCheckpointError("checkpoint_head_hash_invalid")
    if sequence == 0 and head_sha256 != _GENESIS:
        raise ReplayCheckpointError("checkpoint_genesis_invalid")
    if not isinstance(key_id, str) or not key_id.strip():
        raise ReplayCheckpointError("checkpoint_key_id_invalid")
    payload = {"schema_version": SCHEMA_VERSION, "provider_id": provider_id, "sequence": sequence,
               "head_sha256": head_sha256, "key_id": key_id}
    signature = private_key.sign(_DOMAIN + _canonical(payload))
    return {"checkpoint": payload, "signature_base64": base64.b64encode(signature).decode("ascii")}


def verify_registry_checkpoint(
    envelope: dict, *, trusted_public_keys: Mapping[str, bytes], expected_provider_id: str,
    minimum_sequence: int, local_sequence: int, local_head_sha256: str,
    externally_anchored_head_sha256: str | None = None,
) -> dict:
    """Verify signed checkpoint and compare it with local state and external high-water data.

    minimum_sequence and externally_anchored_head_sha256 must come from a
    trusted source that cannot be rolled back with the SQLite registry. If the
    caller supplies only a checkpoint copied beside the database, rollback
    detection is not established.
    """
    if not isinstance(envelope, dict) or set(envelope) != {"checkpoint", "signature_base64"}:
        raise ReplayCheckpointError("checkpoint_envelope_fields_invalid")
    payload = envelope["checkpoint"]
    if not isinstance(payload, dict) or set(payload) != _FIELDS:
        raise ReplayCheckpointError("checkpoint_payload_fields_invalid")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise ReplayCheckpointError("checkpoint_schema_version_unsupported")
    if payload.get("provider_id") != expected_provider_id:
        raise ReplayCheckpointError("checkpoint_provider_mismatch")
    sequence = payload.get("sequence")
    if type(sequence) is not int or sequence < 0 or type(minimum_sequence) is not int or minimum_sequence < 0:
        raise ReplayCheckpointError("checkpoint_sequence_invalid")
    head = payload.get("head_sha256")
    if not isinstance(head, str) or len(head) != 64 or any(c not in "0123456789abcdef" for c in head):
        raise ReplayCheckpointError("checkpoint_head_hash_invalid")
    if sequence == 0 and head != _GENESIS:
        raise ReplayCheckpointError("checkpoint_genesis_invalid")
    key_id = payload.get("key_id")
    public_bytes = trusted_public_keys.get(key_id) if isinstance(key_id, str) else None
    if not isinstance(public_bytes, bytes) or len(public_bytes) != 32:
        raise ReplayCheckpointError("checkpoint_signing_key_not_trusted")
    signature_text = envelope["signature_base64"]
    if not isinstance(signature_text, str):
        raise ReplayCheckpointError("checkpoint_signature_encoding_invalid")
    try:
        signature = base64.b64decode(signature_text.encode("ascii"), validate=True)
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, _DOMAIN + _canonical(payload))
    except (ValueError, UnicodeEncodeError, TypeError, InvalidSignature, base64.binascii.Error) as exc:
        raise ReplayCheckpointError("checkpoint_signature_invalid") from exc
    if sequence < minimum_sequence:
        raise ReplayCheckpointError("checkpoint_behind_external_high_water_mark")
    if externally_anchored_head_sha256 is not None:
        if (not isinstance(externally_anchored_head_sha256, str)
                or len(externally_anchored_head_sha256) != 64
                or any(c not in "0123456789abcdef" for c in externally_anchored_head_sha256)):
            raise ReplayCheckpointError("external_anchor_head_hash_invalid")
        if minimum_sequence == 0 and externally_anchored_head_sha256 != _GENESIS:
            raise ReplayCheckpointError("external_anchor_genesis_invalid")
        if sequence == minimum_sequence and head != externally_anchored_head_sha256:
            raise ReplayCheckpointError("checkpoint_conflicts_with_external_anchor")
    if type(local_sequence) is not int or local_sequence < 0:
        raise ReplayCheckpointError("local_registry_sequence_invalid")
    if local_sequence != sequence or local_head_sha256 != head:
        raise ReplayCheckpointError("local_registry_state_differs_from_checkpoint")
    return {"valid": True, "provider_id": expected_provider_id, "sequence": sequence,
            "head_sha256": head, "rollback_resistance": "EXTERNAL_ANCHOR_REQUIRED",
            "qualification": "NOT_ESTABLISHED"}
