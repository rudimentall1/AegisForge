from copy import deepcopy

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared.replay_registry_checkpoint import (
    ReplayCheckpointError,
    sign_registry_checkpoint,
    verify_registry_checkpoint,
)


def _public_bytes(key):
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _checkpoint(key, sequence=12, head=None):
    return sign_registry_checkpoint(
        provider_id="test-provider",
        sequence=sequence,
        head_sha256=head or ("a" * 64),
        key_id="checkpoint-key",
        private_key=key,
    )


def _verify(envelope, key, **overrides):
    args = {
        "trusted_public_keys": {"checkpoint-key": _public_bytes(key)},
        "expected_provider_id": "test-provider",
        "minimum_sequence": 12,
        "local_sequence": 12,
        "local_head_sha256": "a" * 64,
        "externally_anchored_head_sha256": "a" * 64,
    }
    args.update(overrides)
    return verify_registry_checkpoint(envelope, **args)


def test_signed_checkpoint_matches_external_anchor_and_local_state():
    key = Ed25519PrivateKey.generate()
    result = _verify(_checkpoint(key), key)
    assert result["valid"] is True
    assert result["rollback_resistance"] == "EXTERNAL_ANCHOR_REQUIRED"
    assert result["qualification"] == "NOT_ESTABLISHED"


def test_checkpoint_behind_external_high_water_mark_is_rejected():
    key = Ed25519PrivateKey.generate()
    with pytest.raises(ReplayCheckpointError, match="behind_external_high_water_mark"):
        _verify(_checkpoint(key, sequence=11), key, minimum_sequence=12,
                local_sequence=11, local_head_sha256="a" * 64)


def test_local_registry_rollback_is_detected_against_newer_checkpoint():
    key = Ed25519PrivateKey.generate()
    newer = _checkpoint(key, sequence=12, head="a" * 64)
    with pytest.raises(ReplayCheckpointError, match="local_registry_state_differs"):
        _verify(newer, key, minimum_sequence=12, local_sequence=9,
                local_head_sha256="b" * 64, externally_anchored_head_sha256="a" * 64)


def test_checkpoint_conflicting_with_external_anchor_is_rejected():
    key = Ed25519PrivateKey.generate()
    envelope = _checkpoint(key, sequence=12, head="a" * 64)
    with pytest.raises(ReplayCheckpointError, match="conflicts_with_external_anchor"):
        _verify(envelope, key, externally_anchored_head_sha256="c" * 64)


def test_checkpoint_signature_tampering_is_rejected():
    key = Ed25519PrivateKey.generate()
    envelope = _checkpoint(key)
    altered = deepcopy(envelope)
    altered["checkpoint"]["sequence"] = 13
    with pytest.raises(ReplayCheckpointError, match="signature_invalid"):
        _verify(altered, key, minimum_sequence=0, local_sequence=13)


def test_unknown_checkpoint_signer_is_rejected():
    key = Ed25519PrivateKey.generate()
    with pytest.raises(ReplayCheckpointError, match="signing_key_not_trusted"):
        verify_registry_checkpoint(
            _checkpoint(key), trusted_public_keys={}, expected_provider_id="test-provider",
            minimum_sequence=12, local_sequence=12, local_head_sha256="a" * 64,
        )


def test_checkpoint_provider_mismatch_is_rejected():
    key = Ed25519PrivateKey.generate()
    with pytest.raises(ReplayCheckpointError, match="provider_mismatch"):
        _verify(_checkpoint(key), key, expected_provider_id="other-provider")


def test_checkpoint_rejects_unknown_envelope_fields():
    key = Ed25519PrivateKey.generate()
    envelope = _checkpoint(key)
    envelope["trusted"] = True
    with pytest.raises(ReplayCheckpointError, match="envelope_fields_invalid"):
        _verify(envelope, key)


def test_signer_rejects_non_genesis_hash_at_sequence_zero():
    key = Ed25519PrivateKey.generate()
    with pytest.raises(ReplayCheckpointError, match="checkpoint_genesis_invalid"):
        _checkpoint(key, sequence=0, head="a" * 64)


def test_verifier_rejects_signed_non_genesis_checkpoint_at_sequence_zero():
    key = Ed25519PrivateKey.generate()
    # Simulate a legacy or malicious signer producing a correctly signed but
    # semantically impossible genesis statement.
    from shared.replay_registry_checkpoint import SCHEMA_VERSION, _DOMAIN, _canonical
    import base64
    payload = {
        "schema_version": SCHEMA_VERSION,
        "provider_id": "test-provider",
        "sequence": 0,
        "head_sha256": "a" * 64,
        "key_id": "checkpoint-key",
    }
    envelope = {
        "checkpoint": payload,
        "signature_base64": base64.b64encode(key.sign(_DOMAIN + _canonical(payload))).decode("ascii"),
    }
    with pytest.raises(ReplayCheckpointError, match="checkpoint_genesis_invalid"):
        _verify(envelope, key, minimum_sequence=0, local_sequence=0,
                local_head_sha256="a" * 64, externally_anchored_head_sha256="0" * 64)


def test_verifier_rejects_malformed_external_anchor_head():
    key = Ed25519PrivateKey.generate()
    with pytest.raises(ReplayCheckpointError, match="external_anchor_head_hash_invalid"):
        _verify(_checkpoint(key), key, externally_anchored_head_sha256="not-a-hash")


def test_verifier_rejects_non_genesis_external_anchor_at_sequence_zero():
    key = Ed25519PrivateKey.generate()
    with pytest.raises(ReplayCheckpointError, match="external_anchor_genesis_invalid"):
        _verify(_checkpoint(key, sequence=0, head="0" * 64), key,
                minimum_sequence=0, local_sequence=0, local_head_sha256="0" * 64,
                externally_anchored_head_sha256="a" * 64)
