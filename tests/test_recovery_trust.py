import pytest

from shared.capability_signing import CapabilitySigner
from shared.recovery_trust import (
    RecoveryAttestor,
    RecoveryAttestorRegistry,
    RecoveryTrustError,
)


def test_registry_accepts_canonical_attestor():
    signer = CapabilitySigner.generate()
    attestor = RecoveryAttestor(
        key_id=signer.key_id,
        public_key=signer.public_key,
        name="AegisForge Recovery Attestor",
    )
    registry = RecoveryAttestorRegistry([attestor])

    assert registry.get(signer.key_id) == attestor
    assert registry.require(signer.key_id, signer.public_key) == attestor


def test_registry_rejects_unknown_key():
    signer = CapabilitySigner.generate()
    registry = RecoveryAttestorRegistry()

    with pytest.raises(RecoveryTrustError, match="untrusted_attestor"):
        registry.require(signer.key_id, signer.public_key)


def test_registry_rejects_public_key_substitution():
    signer = CapabilitySigner.generate()
    other = CapabilitySigner.generate()
    registry = RecoveryAttestorRegistry([
        RecoveryAttestor(
            key_id=signer.key_id,
            public_key=signer.public_key,
            name="trusted",
        )
    ])

    with pytest.raises(RecoveryTrustError, match="attestor_key_mismatch"):
        registry.require(signer.key_id, other.public_key)


def test_registry_rejects_disabled_attestor():
    signer = CapabilitySigner.generate()
    registry = RecoveryAttestorRegistry([
        RecoveryAttestor(
            key_id=signer.key_id,
            public_key=signer.public_key,
            name="disabled",
            enabled=False,
        )
    ])

    with pytest.raises(RecoveryTrustError, match="attestor_disabled"):
        registry.require(signer.key_id, signer.public_key)


def test_registry_rejects_noncanonical_key_id():
    signer = CapabilitySigner.generate()

    with pytest.raises(RecoveryTrustError, match="attestor_key_id_mismatch"):
        RecoveryAttestorRegistry([
            RecoveryAttestor(
                key_id="wrong",
                public_key=signer.public_key,
                name="bad",
            )
        ])


def test_registry_lifecycle_suspend_resume_revoke():
    signer = CapabilitySigner.generate()
    registry = RecoveryAttestorRegistry([
        RecoveryAttestor(
            key_id=signer.key_id,
            public_key=signer.public_key,
            name="lifecycle",
        )
    ])

    assert registry.status(signer.key_id) == "ACTIVE"
    registry.transition(signer.key_id, "SUSPENDED", "investigate attestor")
    with pytest.raises(RecoveryTrustError, match="attestor_suspended"):
        registry.require(signer.key_id, signer.public_key)

    registry.transition(signer.key_id, "ACTIVE", "investigation cleared")
    assert registry.require(signer.key_id, signer.public_key).key_id == signer.key_id

    registry.transition(signer.key_id, "REVOKED", "key compromise")
    with pytest.raises(RecoveryTrustError, match="attestor_revoked"):
        registry.require(signer.key_id, signer.public_key)


def test_registry_rejects_invalid_lifecycle_transitions_and_requires_reason():
    signer = CapabilitySigner.generate()
    registry = RecoveryAttestorRegistry([
        RecoveryAttestor(
            key_id=signer.key_id,
            public_key=signer.public_key,
            name="lifecycle",
        )
    ])

    with pytest.raises(RecoveryTrustError, match="attestor_transition_reason_required"):
        registry.transition(signer.key_id, "SUSPENDED", " ")

    registry.transition(signer.key_id, "REVOKED", "retired")
    with pytest.raises(RecoveryTrustError, match="invalid_attestor_transition"):
        registry.transition(signer.key_id, "ACTIVE", "restore")


def test_registry_history_is_auditable():
    signer = CapabilitySigner.generate()
    registry = RecoveryAttestorRegistry([
        RecoveryAttestor(
            key_id=signer.key_id,
            public_key=signer.public_key,
            name="history",
        )
    ])

    registry.transition(signer.key_id, "SUSPENDED", "temporary suspension")
    history = registry.history(signer.key_id)

    assert [event["to_status"] for event in history] == ["ACTIVE", "SUSPENDED"]
    assert history[1]["from_status"] == "ACTIVE"
    assert history[1]["reason"] == "temporary suspension"
    assert all(event["occurred_at"] for event in history)
