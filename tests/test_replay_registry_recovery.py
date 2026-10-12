import json
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared.attestation_replay_registry import verify_and_record_attestation
from shared.experiment_dossier import canonical_json
from shared.replay_registry_recovery import ReplayRecoveryError, build_replay_recovery_plan
from test_attestation_replay_registry import _dossier, _envelope, _public_bytes


def _record(path, key, run_id, nonce):
    dossier = _dossier(run_id, nonce)
    envelope = _envelope(dossier, key)
    result = verify_and_record_attestation(
        dossier, envelope, trusted_public_keys={"pinned-runner-key": _public_bytes(key)},
        database_path=path,
    )
    return dossier, envelope, result


def test_recovery_plan_is_read_only_and_verifies_signed_suffix(tmp_path):
    path = tmp_path / "registry.sqlite3"
    key = Ed25519PrivateKey.generate()
    _, _, first = _record(path, key, "recover-one", "recover-nonce-one")
    _record(path, key, "recover-two", "recover-nonce-two")
    with sqlite3.connect(path) as db:
        before = db.execute("SELECT sequence, head_sha256 FROM attestation_replay_journal_state").fetchone()

    plan = build_replay_recovery_plan(
        path, provider_id="test-provider", anchor_sequence=1,
        anchor_head_sha256=first["journal"]["head_sha256"],
        trusted_public_keys={"pinned-runner-key": _public_bytes(key)},
    )

    assert plan["action"] == "OPERATOR_REVIEW_REQUIRED"
    assert plan["anchor"]["sequence"] == 1
    assert plan["terminal"]["sequence"] == 2
    assert len(plan["suffix"]) == 1
    assert plan["suffix"][0]["run_id"] == "recover-two"
    assert plan["writes_performed"] is False
    assert plan["anchor_updated"] is False
    assert len(plan["plan_sha256"]) == 64
    with sqlite3.connect(path) as db:
        after = db.execute("SELECT sequence, head_sha256 FROM attestation_replay_journal_state").fetchone()
    assert after == before


def test_recovery_plan_rejects_anchor_head_not_in_local_history(tmp_path):
    path = tmp_path / "registry.sqlite3"
    key = Ed25519PrivateKey.generate()
    _record(path, key, "recover-one", "recover-nonce-one")
    with pytest.raises(ReplayRecoveryError, match="recovery_anchor_does_not_match_local_history"):
        build_replay_recovery_plan(
            path, provider_id="test-provider", anchor_sequence=1,
            anchor_head_sha256="f" * 64,
            trusted_public_keys={"pinned-runner-key": _public_bytes(key)},
        )


def test_recovery_plan_rejects_tampered_stored_receipt(tmp_path):
    path = tmp_path / "registry.sqlite3"
    key = Ed25519PrivateKey.generate()
    _record(path, key, "recover-one", "recover-nonce-one")
    with sqlite3.connect(path) as db:
        row = db.execute("SELECT envelope_json FROM attestation_replay_evidence").fetchone()
        envelope = json.loads(row[0])
        envelope["signature"] = "AAAA"
        db.execute("UPDATE attestation_replay_evidence SET envelope_json=?", (canonical_json(envelope),))
        db.commit()
    with pytest.raises(ReplayRecoveryError, match="recovery_signed_evidence_invalid"):
        build_replay_recovery_plan(
            path, provider_id="test-provider", anchor_sequence=0,
            anchor_head_sha256="0" * 64,
            trusted_public_keys={"pinned-runner-key": _public_bytes(key)},
        )


def test_recovery_plan_rejects_anchor_ahead_of_local_registry(tmp_path):
    path = tmp_path / "registry.sqlite3"
    key = Ed25519PrivateKey.generate()
    _record(path, key, "recover-one", "recover-nonce-one")
    with pytest.raises(ReplayRecoveryError, match="recovery_anchor_ahead_of_local_registry"):
        build_replay_recovery_plan(
            path, provider_id="test-provider", anchor_sequence=2,
            anchor_head_sha256="a" * 64,
            trusted_public_keys={"pinned-runner-key": _public_bytes(key)},
        )


def test_revalidation_rebuilds_plan_against_current_anchor_and_registry(tmp_path):
    from shared.replay_registry_recovery import revalidate_replay_recovery_plan

    path = tmp_path / "registry.sqlite3"
    key = Ed25519PrivateKey.generate()
    _, _, first = _record(path, key, "revalidate-one", "revalidate-nonce-one")
    trusted = {"pinned-runner-key": _public_bytes(key)}
    plan = build_replay_recovery_plan(
        path, provider_id="test-provider", anchor_sequence=1,
        anchor_head_sha256=first["journal"]["head_sha256"],
        trusted_public_keys=trusted,
    )

    result = revalidate_replay_recovery_plan(
        path, plan=plan, provider_id="test-provider",
        current_anchor_sequence=1,
        current_anchor_head_sha256=first["journal"]["head_sha256"],
        trusted_public_keys=trusted,
    )
    assert result["valid"] is True
    assert result["plan_sha256"] == plan["plan_sha256"]
    assert result["writes_performed"] is False

    _record(path, key, "revalidate-two", "revalidate-nonce-two")
    with pytest.raises(ReplayRecoveryError, match="recovery_plan_stale_or_tampered"):
        revalidate_replay_recovery_plan(
            path, plan=plan, provider_id="test-provider",
            current_anchor_sequence=1,
            current_anchor_head_sha256=first["journal"]["head_sha256"],
            trusted_public_keys=trusted,
        )


def test_revalidation_rejects_plan_mutation(tmp_path):
    from shared.replay_registry_recovery import revalidate_replay_recovery_plan

    path = tmp_path / "registry.sqlite3"
    key = Ed25519PrivateKey.generate()
    _, _, first = _record(path, key, "revalidate-tamper", "revalidate-nonce-tamper")
    trusted = {"pinned-runner-key": _public_bytes(key)}
    plan = build_replay_recovery_plan(
        path, provider_id="test-provider", anchor_sequence=1,
        anchor_head_sha256=first["journal"]["head_sha256"],
        trusted_public_keys=trusted,
    )
    plan["suffix"].append({"sequence": 999})
    with pytest.raises(ReplayRecoveryError, match="recovery_plan_stale_or_tampered"):
        revalidate_replay_recovery_plan(
            path, plan=plan, provider_id="test-provider",
            current_anchor_sequence=1,
            current_anchor_head_sha256=first["journal"]["head_sha256"],
            trusted_public_keys=trusted,
        )


def test_recovery_plan_rejects_deleted_evidence_even_when_journal_remains(tmp_path):
    path = tmp_path / "registry.sqlite3"
    key = Ed25519PrivateKey.generate()
    _record(path, key, "recover-missing-evidence", "recover-missing-evidence-nonce")
    with sqlite3.connect(path) as db:
        db.execute("DELETE FROM attestation_replay_evidence WHERE provider_id=?", ("test-provider",))
        db.commit()

    with pytest.raises(ReplayRecoveryError, match="recovery_journal_or_evidence_count_mismatch"):
        build_replay_recovery_plan(
            path, provider_id="test-provider", anchor_sequence=0,
            anchor_head_sha256="0" * 64,
            trusted_public_keys={"pinned-runner-key": _public_bytes(key)},
        )
