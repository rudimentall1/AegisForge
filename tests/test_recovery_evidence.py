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
