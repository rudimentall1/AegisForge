import pytest

from shared.capability_signing import CapabilitySigner
from shared.recovery_trust import (
    RecoveryAttestor,
    RecoveryAttestorStatus,
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



def test_registry_persists_lifecycle_across_restart(tmp_path):
    signer = CapabilitySigner.generate()
    db = tmp_path / "recovery-attestors.sqlite3"
    attestor = RecoveryAttestor(
        key_id=signer.key_id,
        public_key=signer.public_key,
        name="persistent",
    )

    first = RecoveryAttestorRegistry([attestor], store=db)
    first.transition(signer.key_id, RecoveryAttestorStatus.SUSPENDED, "incident review")
    assert first.status(signer.key_id) == RecoveryAttestorStatus.SUSPENDED

    second = RecoveryAttestorRegistry(store=db)
    assert second.status(signer.key_id) == RecoveryAttestorStatus.SUSPENDED
    assert len(second.history(signer.key_id)) == 2
    with pytest.raises(RecoveryTrustError, match="attestor_suspended"):
        second.require(signer.key_id, signer.public_key)

    second.transition(signer.key_id, RecoveryAttestorStatus.ACTIVE, "review cleared")
    third = RecoveryAttestorRegistry(store=db)
    assert third.status(signer.key_id) == RecoveryAttestorStatus.ACTIVE
    assert len(third.history(signer.key_id)) == 3
    assert third.require(signer.key_id, signer.public_key).key_id == signer.key_id


def test_registry_persists_revocation_and_cannot_restore(tmp_path):
    signer = CapabilitySigner.generate()
    db = tmp_path / "recovery-attestors.sqlite3"
    attestor = RecoveryAttestor(
        key_id=signer.key_id,
        public_key=signer.public_key,
        name="revoked",
    )

    registry = RecoveryAttestorRegistry([attestor], store=db)
    registry.transition(signer.key_id, RecoveryAttestorStatus.REVOKED, "key compromised")

    restarted = RecoveryAttestorRegistry(store=db)
    assert restarted.status(signer.key_id) == RecoveryAttestorStatus.REVOKED
    with pytest.raises(RecoveryTrustError, match="attestor_revoked"):
        restarted.require(signer.key_id, signer.public_key)
    with pytest.raises(RecoveryTrustError, match="invalid_attestor_transition"):
        restarted.transition(signer.key_id, RecoveryAttestorStatus.ACTIVE, "attempt restore")


def test_registry_persistent_transition_is_atomic_on_failure(tmp_path):
    signer = CapabilitySigner.generate()
    db = tmp_path / "recovery-attestors.sqlite3"
    registry = RecoveryAttestorRegistry([
        RecoveryAttestor(
            key_id=signer.key_id,
            public_key=signer.public_key,
            name="atomic",
        )
    ], store=db)

    registry.transition(signer.key_id, RecoveryAttestorStatus.SUSPENDED, "suspend")
    restarted = RecoveryAttestorRegistry(store=db)
    assert restarted.status(signer.key_id) == RecoveryAttestorStatus.SUSPENDED
    assert [event["to_status"] for event in restarted.history(signer.key_id)] == ["ACTIVE", "SUSPENDED"]


def test_registry_history_hash_chain_is_verifiable():
    signer = CapabilitySigner.generate()
    registry = RecoveryAttestorRegistry([
        RecoveryAttestor(
            key_id=signer.key_id,
            public_key=signer.public_key,
            name="hash-chain",
        )
    ])
    registry.transition(signer.key_id, RecoveryAttestorStatus.SUSPENDED, "incident")
    result = registry.verify_history(signer.key_id)

    assert result["valid"] is True
    assert result["events"] == 2
    assert len(result["head_hash"]) == 64
    history = registry.history(signer.key_id)
    assert history[0]["prev_hash"] == "0" * 64
    assert history[1]["prev_hash"] == history[0]["event_hash"]


def test_persistent_history_detects_source_record_tampering(tmp_path):
    signer = CapabilitySigner.generate()
    db = tmp_path / "attestors.sqlite3"
    registry = RecoveryAttestorRegistry([
        RecoveryAttestor(
            key_id=signer.key_id,
            public_key=signer.public_key,
            name="tamper",
        )
    ], store=db)
    registry.transition(signer.key_id, RecoveryAttestorStatus.SUSPENDED, "incident")

    import sqlite3
    conn = sqlite3.connect(db)
    conn.execute(
        "UPDATE recovery_attestor_history SET reason = ? WHERE key_id = ? AND event_id = 2",
        ("tampered", signer.key_id),
    )
    conn.commit()
    conn.close()

    restarted = RecoveryAttestorRegistry(store=db)
    with pytest.raises(RecoveryTrustError, match="trust_history_event_hash_mismatch"):
        restarted.verify_history(signer.key_id)


def test_persistent_history_detects_chain_link_tampering(tmp_path):
    signer = CapabilitySigner.generate()
    db = tmp_path / "attestors.sqlite3"
    registry = RecoveryAttestorRegistry([
        RecoveryAttestor(
            key_id=signer.key_id,
            public_key=signer.public_key,
            name="chain-tamper",
        )
    ], store=db)
    registry.transition(signer.key_id, RecoveryAttestorStatus.SUSPENDED, "incident")
    registry.transition(signer.key_id, RecoveryAttestorStatus.ACTIVE, "cleared")

    import sqlite3
    conn = sqlite3.connect(db)
    conn.execute(
        "UPDATE recovery_attestor_history_integrity SET prev_hash = ? "
        "WHERE key_id = ? AND event_id = 3",
        ("f" * 64, signer.key_id),
    )
    conn.commit()
    conn.close()

    restarted = RecoveryAttestorRegistry(store=db)
    with pytest.raises(RecoveryTrustError, match="trust_history_prev_hash_mismatch"):
        restarted.verify_history(signer.key_id)


def test_persistent_history_detects_missing_integrity_record(tmp_path):
    signer = CapabilitySigner.generate()
    db = tmp_path / "attestors.sqlite3"
    registry = RecoveryAttestorRegistry([
        RecoveryAttestor(
            key_id=signer.key_id,
            public_key=signer.public_key,
            name="missing-integrity",
        )
    ], store=db)
    registry.transition(signer.key_id, RecoveryAttestorStatus.SUSPENDED, "incident")

    import sqlite3
    conn = sqlite3.connect(db)
    conn.execute(
        "DELETE FROM recovery_attestor_history_integrity WHERE key_id = ? AND event_id = 2",
        (signer.key_id,),
    )
    conn.commit()
    conn.close()

    restarted = RecoveryAttestorRegistry(store=db)
    with pytest.raises(RecoveryTrustError, match="trust_history_missing"):
        restarted.verify_history(signer.key_id)
