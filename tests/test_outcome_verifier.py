import pytest

from shared.capability_policy import ActionIntent
from shared.execution_gate import ExecutionReceipt
from shared.outcome_verifier import FilesystemOutcomeVerifier, OutcomeVerificationError


def _intent(target="workspace/obsolete.txt"):
    return ActionIntent(
        role="developer",
        action="delete",
        target=target,
        resource="staging_filesystem",
        destination="staging",
        data_scope="source_code",
        irreversible=True,
        requires_network=False,
        requires_shell=False,
        requires_filesystem=True,
        financial=False,
        privileged=False,
        read_only=False,
        evidence_required=True,
    )


def _receipt(intent, result=None, intent_hash_value=None):
    from shared.capability_grant import intent_hash

    return ExecutionReceipt(
        receipt_id="receipt_test",
        task_id="task_test",
        grant_id="grant_test",
        nonce="nonce_test",
        intent_hash=intent_hash_value or intent_hash(intent),
        policy_version="capability-policy-v1",
        action="delete",
        target=intent.target,
        authorized_scope="staging",
        status="EXECUTED",
        executed_at="2026-10-01T00:00:00+00:00",
        result=result if result is not None else {"deleted": intent.target},
    )


def test_filesystem_recovery_confirms_delete_without_receipt(tmp_path):
    target = tmp_path / "workspace" / "obsolete.txt"
    target.parent.mkdir()
    intent = _intent()
    outcome = FilesystemOutcomeVerifier(tmp_path).verify_recovery(
        intent,
        {"type": "state_match", "verifier": "filesystem_independent_v1", "expected_state": "ABSENT"},
    )
    assert outcome["status"] == "SIDE_EFFECT_CONFIRMED"
    assert outcome["observed_state"] == "ABSENT"


def test_filesystem_recovery_allows_retry_when_delete_did_not_happen(tmp_path):
    target = tmp_path / "workspace" / "obsolete.txt"
    target.parent.mkdir()
    target.write_text("still here")
    intent = _intent()
    outcome = FilesystemOutcomeVerifier(tmp_path).verify_recovery(
        intent,
        {"type": "state_match", "verifier": "filesystem_independent_v1", "expected_state": "ABSENT"},
    )
    assert outcome["status"] == "SAFE_TO_RETRY"
    assert outcome["observed_state"] == "PRESENT"


def test_filesystem_outcome_is_proven_from_observed_state(tmp_path):
    target = tmp_path / "workspace" / "obsolete.txt"
    target.parent.mkdir()
    target.write_text("gone")
    target.unlink()

    intent = _intent()
    outcome = FilesystemOutcomeVerifier(tmp_path).verify(intent, _receipt(intent))

    assert outcome["status"] == "PROVEN"
    assert outcome["observed_state"] == "ABSENT"
    assert outcome["verifier"] == "filesystem_independent_v1"
    assert "filesystem_absence" in outcome["checks"]


def test_forged_receipt_fails_when_effect_was_not_observed(tmp_path):
    target = tmp_path / "workspace" / "obsolete.txt"
    target.parent.mkdir()
    target.write_text("still here")

    with pytest.raises(OutcomeVerificationError, match="filesystem_effect_not_observed"):
        FilesystemOutcomeVerifier(tmp_path).verify(_intent(), _receipt(_intent()))


def test_tampered_receipt_intent_binding_fails(tmp_path):
    intent = _intent()
    with pytest.raises(OutcomeVerificationError, match="receipt_intent_hash_mismatch"):
        FilesystemOutcomeVerifier(tmp_path).verify(
            intent,
            _receipt(intent, intent_hash_value="0" * 64),
        )


def test_tampered_receipt_result_fails_even_when_effect_exists(tmp_path):
    target = tmp_path / "workspace" / "obsolete.txt"
    target.parent.mkdir()
    target.write_text("gone")
    target.unlink()

    intent = _intent()
    forged = _receipt(intent, result={"deleted": "workspace/other.txt"})

    with pytest.raises(OutcomeVerificationError, match="receipt_result_mismatch"):
        FilesystemOutcomeVerifier(tmp_path).verify(intent, forged)