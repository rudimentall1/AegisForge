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
