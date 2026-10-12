"""Strict loader for out-of-band runner public-key trust bundles.

Bundles contain public keys only. The file's delivery and integrity must be
protected outside this module; parsing a bundle does not make it trustworthy.
"""
from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path
from typing import Any

from shared.runner_trust_policy import RunnerTrustKey, RunnerTrustPolicyError, _parse_utc

SCHEMA_VERSION = "evm-key-forensics-runner-trust-v1"
_ROOT_FIELDS = {"schema_version", "keys"}
_KEY_FIELDS = {"key_id", "provider_id", "public_key_base64", "not_before", "not_after", "revoked_at"}


class RunnerTrustBundleError(ValueError):
    """Raised when a trust bundle is malformed or ambiguous."""


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RunnerTrustBundleError(f"duplicate_json_key:{key}")
        result[key] = value
    return result


def load_runner_trust_bundle(source: str | Path | bytes) -> dict[str, RunnerTrustKey]:
    """Parse and validate a JSON trust bundle from bytes or a file path.

    Public Ed25519 keys must be 32 raw bytes encoded as standard Base64. Unknown
    fields are rejected to avoid silently ignoring policy typos. This function
    does not authenticate the bundle's origin.
    """
    try:
        if isinstance(source, bytes):
            raw = source
        else:
            raw = Path(source).read_bytes()
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_object_without_duplicate_keys)
    except RunnerTrustBundleError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
        raise RunnerTrustBundleError("trust_bundle_unreadable_or_invalid_json") from exc

    if not isinstance(parsed, dict) or set(parsed) != _ROOT_FIELDS:
        raise RunnerTrustBundleError("trust_bundle_root_fields_invalid")
    if parsed.get("schema_version") != SCHEMA_VERSION:
        raise RunnerTrustBundleError("trust_bundle_schema_version_unsupported")
    entries = parsed.get("keys")
    if not isinstance(entries, list) or not entries:
        raise RunnerTrustBundleError("trust_bundle_keys_must_be_nonempty_list")

    result: dict[str, RunnerTrustKey] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != _KEY_FIELDS:
            raise RunnerTrustBundleError(f"trust_bundle_key_fields_invalid:{index}")
        key_id = entry.get("key_id")
        provider_id = entry.get("provider_id")
        if not isinstance(key_id, str) or not key_id.strip() or not isinstance(provider_id, str) or not provider_id.strip():
            raise RunnerTrustBundleError(f"trust_bundle_identity_invalid:{index}")
        if key_id in result:
            raise RunnerTrustBundleError(f"duplicate_key_id:{key_id}")
        try:
            encoded = entry.get("public_key_base64")
            if not isinstance(encoded, str):
                raise ValueError("key_not_string")
            public_key = base64.b64decode(encoded.encode("ascii"), validate=True)
        except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
            raise RunnerTrustBundleError(f"public_key_base64_invalid:{key_id}") from exc
        if len(public_key) != 32:
            raise RunnerTrustBundleError(f"ed25519_public_key_length_invalid:{key_id}")
        not_before, not_after = entry.get("not_before"), entry.get("not_after")
        try:
            before_dt, after_dt = _parse_utc(not_before, "not_before"), _parse_utc(not_after, "not_after")
            if before_dt >= after_dt:
                raise RunnerTrustBundleError(f"key_validity_interval_invalid:{key_id}")
            revoked_at = entry.get("revoked_at")
            if revoked_at is not None:
                _parse_utc(revoked_at, "revoked_at")
        except RunnerTrustPolicyError as exc:
            raise RunnerTrustBundleError(f"key_timestamp_invalid:{key_id}:{exc}") from exc
        result[key_id] = RunnerTrustKey(
            provider_id=provider_id,
            public_key=public_key,
            not_before=not_before,
            not_after=not_after,
            revoked_at=revoked_at,
        )
    return result
