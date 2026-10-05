import sqlite3

from shared.recovery_evidence import GENESIS_HASH, RecoveryEvidenceChain


def test_recovery_evidence_chain_is_hash_linked_and_verifiable():
    db = sqlite3.connect(":memory:")
    chain = RecoveryEvidenceChain(db)

    first = chain.append(
        "recovery-1", "attempt-1", "RECOVERY_OPENED", {"state": "RUNNING"}
    )
    second = chain.append(
        "recovery-1",
        "attempt-1",
        "VERIFICATION_DECISION",
        {"decision": "SAFE_TO_RETRY"},
    )
    third = chain.append(
        "recovery-1",
        "attempt-1",
        "RETRY_CREATED",
        {"retry_attempt_id": "attempt-2"},
    )

    events = chain.events("recovery-1")
    assert len(events) == 3
    assert events[0]["prev_hash"] == GENESIS_HASH
    assert events[1]["prev_hash"] == first["event_hash"]
    assert events[2]["prev_hash"] == second["event_hash"]
    assert chain.verify("recovery-1")["valid"] is True
    assert chain.verify("recovery-1")["head_hash"] == third["event_hash"]


def test_recovery_evidence_detects_tampering():
    db = sqlite3.connect(":memory:")
    chain = RecoveryEvidenceChain(db)
    event = chain.append(
        "recovery-1", "attempt-1", "RECOVERY_OPENED", {"state": "RUNNING"}
    )

    db.execute(
        "UPDATE recovery_evidence_events SET payload=? WHERE event_hash=?",
        ('{"state":"SUCCEEDED"}', event["event_hash"]),
    )
    db.commit()

    result = chain.verify("recovery-1")
    assert result["valid"] is False
    assert result["error"] == "event_hash_mismatch"


def test_recovery_evidence_exports_and_verifies_portable_artifact():
    db = sqlite3.connect(":memory:")
    chain = RecoveryEvidenceChain(db)
    chain.append("recovery-1", "attempt-1", "RECOVERY_OPENED", {"state": "RUNNING"})
    chain.append(
        "recovery-1",
        "attempt-1",
        "VERIFICATION_DECISION",
        {"decision": "SAFE_TO_RETRY"},
    )
    artifact = chain.export_artifact("recovery-1")

    assert artifact["schema_version"] == "recovery-evidence-v1"
    assert RecoveryEvidenceChain.verify_artifact(artifact)["valid"] is True

    tampered = dict(artifact)
    tampered["events"] = [dict(event) for event in artifact["events"]]
    tampered["events"][1]["payload"] = {"decision": "SIDE_EFFECT_CONFIRMED"}
    assert RecoveryEvidenceChain.verify_artifact(tampered)["error"] == "event_hash_mismatch"


def test_recovery_evidence_rejects_portable_artifact_head_tampering():
    db = sqlite3.connect(":memory:")
    chain = RecoveryEvidenceChain(db)
    chain.append("recovery-1", "attempt-1", "RECOVERY_OPENED", {"state": "RUNNING"})
    artifact = chain.export_artifact("recovery-1")

    tampered = dict(artifact)
    tampered["head_hash"] = GENESIS_HASH
    assert RecoveryEvidenceChain.verify_artifact(tampered)["error"] == "head_hash_mismatch"
