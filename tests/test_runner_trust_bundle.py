import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from shared.runner_trust_bundle import RunnerTrustBundleError, SCHEMA_VERSION, load_runner_trust_bundle


def _public_key():
    key = Ed25519PrivateKey.generate()
    return key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def _entry(public_key=None, **overrides):
    item = {
        "key_id": "runner-key-01", "provider_id": "synthetic-provider",
        "public_key_base64": base64.b64encode(public_key or _public_key()).decode("ascii"),
        "not_before": "2026-10-01T00:00:00Z", "not_after": "2027-10-01T00:00:00Z", "revoked_at": None,
    }
    item.update(overrides)
    return item


def _bundle(entries=None, **overrides):
    value = {"schema_version": SCHEMA_VERSION, "keys": entries or [_entry()]}
    value.update(overrides)
    return json.dumps(value).encode("utf-8")


def test_load_valid_public_key_bundle():
    public_key = _public_key()
    result = load_runner_trust_bundle(_bundle([_entry(public_key)]))
    assert result["runner-key-01"].public_key == public_key
    assert result["runner-key-01"].provider_id == "synthetic-provider"


def test_reject_unknown_root_fields():
    with pytest.raises(RunnerTrustBundleError, match="root_fields_invalid"):
        load_runner_trust_bundle(_bundle(extra="ignored-if-permissive"))


def test_reject_unknown_key_fields():
    with pytest.raises(RunnerTrustBundleError, match="key_fields_invalid"):
        load_runner_trust_bundle(_bundle([_entry(extra_policy="typo")]))


def test_reject_duplicate_key_ids():
    entry = _entry()
    with pytest.raises(RunnerTrustBundleError, match="duplicate_key_id"):
        load_runner_trust_bundle(_bundle([entry, dict(entry)]))


def test_reject_duplicate_json_object_keys():
    raw = b'{"schema_version":"evm-key-forensics-runner-trust-v1","schema_version":"evm-key-forensics-runner-trust-v1","keys":[]}'
    with pytest.raises(RunnerTrustBundleError, match="duplicate_json_key"):
        load_runner_trust_bundle(raw)


def test_reject_invalid_base64_and_wrong_key_length():
    with pytest.raises(RunnerTrustBundleError, match="public_key_base64_invalid"):
        load_runner_trust_bundle(_bundle([_entry(public_key=b"x" * 32, public_key_base64="***")]))
    with pytest.raises(RunnerTrustBundleError, match="ed25519_public_key_length_invalid"):
        load_runner_trust_bundle(_bundle([_entry(public_key=b"short")]))


def test_reject_naive_or_inverted_validity_interval():
    with pytest.raises(RunnerTrustBundleError, match="key_timestamp_invalid"):
        load_runner_trust_bundle(_bundle([_entry(not_before="2026-10-01T00:00:00")] ))
    with pytest.raises(RunnerTrustBundleError, match="key_validity_interval_invalid"):
        load_runner_trust_bundle(_bundle([_entry(not_before="2027-01-01T00:00:00Z", not_after="2026-01-01T00:00:00Z")]))


def test_reject_empty_key_list_and_unknown_schema():
    with pytest.raises(RunnerTrustBundleError, match="keys_must_be_nonempty"):
        load_runner_trust_bundle(_bundle([]))
    with pytest.raises(RunnerTrustBundleError, match="schema_version_unsupported"):
        load_runner_trust_bundle(_bundle(schema_version="v0"))
