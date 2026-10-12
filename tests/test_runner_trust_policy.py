import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared.experiment_dossier import canonical_json
from shared.lab_execution_receipt import build_receipt, sign_receipt
from shared.runner_trust_policy import RunnerTrustKey, RunnerTrustPolicyError, verify_with_runner_trust_policy


def _sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _dossier(run_id="policy-run-001", nonce="policy-nonce-001", completed="2026-10-12T06:00:03Z"):
    argv = ["python", "-m", "pytest", "tests/test_synthetic_fixture.py", "-q"]
    return {
        "schema_version": "evm-key-forensics-experiment-dossier-v1", "experiment_id": "synthetic-source-check-v1",
        "run_id": run_id, "nonce": nonce,
        "source": {"repository": "https://github.com/rudimentall1/AegisForge", "revision": "a" * 40},
        "fixture": {"fixture_id": "fixture-synthetic-001", "sha256": _sha("fixture")},
        "command": {"argv": argv, "argv_sha256": _sha(canonical_json(argv))},
        "harness": {"harness_sha256": _sha("harness"), "build_recipe_sha256": _sha("build recipe")},
        "runner": {"provider_id": "test-provider", "runner_id": "runner-01", "image_digest": None},
        "execution": {"started_at": "2026-10-12T06:00:00Z", "completed_at": completed, "exit_code": 0, "timed_out": False, "test_passed": True},
        "result_sha256": _sha("result"), "artifacts": [{"name": "result.json", "sha256": _sha("artifact")}],
        "safety": {"scope": "synthetic_only", "historical_code_executed": False, "real_key_material_handled": False},
    }


def _public_bytes(key):
    return key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def _envelope(dossier, key):
    receipt = build_receipt(
        run_id=dossier["run_id"], experiment_id=dossier["experiment_id"],
        inputs={"source_repository": dossier["source"]["repository"], "source_revision": dossier["source"]["revision"],
                "fixture_id": dossier["fixture"]["fixture_id"], "fixture_sha256": dossier["fixture"]["sha256"],
                "argv": dossier["command"]["argv"], "argv_sha256": dossier["command"]["argv_sha256"],
                "harness_sha256": dossier["harness"]["harness_sha256"], "build_recipe_sha256": dossier["harness"]["build_recipe_sha256"],
                "provider_id": dossier["runner"]["provider_id"], "runner_id": dossier["runner"]["runner_id"],
                "image_digest": dossier["runner"]["image_digest"], "nonce": dossier["nonce"], "safety": dossier["safety"]},
        execution={"started_at": dossier["execution"]["started_at"], "completed_at": dossier["execution"]["completed_at"],
                   "exit_code": dossier["execution"]["exit_code"], "timed_out": dossier["execution"]["timed_out"],
                   "test_passed": dossier["execution"]["test_passed"], "result_sha256": dossier["result_sha256"]},
        artifacts={"items": [{"name": item["name"], "sha256": item["sha256"]} for item in dossier["artifacts"]]},
    )
    return sign_receipt(receipt, private_key=key, key_id="policy-key")


def _run(dossier, envelope, key, path, **kwargs):
    trust_values = {"provider_id": "test-provider", "public_key": _public_bytes(key),
                    "not_before": "2026-10-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"}
    trust_values.update(kwargs.pop("trust_overrides", {}))
    trust = RunnerTrustKey(**trust_values)
    return verify_with_runner_trust_policy(
        dossier, envelope, trusted_keys={"policy-key": trust}, database_path=path,
        now=datetime(2026, 10, 12, 6, 1, tzinfo=timezone.utc), **kwargs)


def test_valid_key_and_fresh_receipt_pass_but_stay_unqualified(tmp_path):
    dossier, key = _dossier(), Ed25519PrivateKey.generate()
    result = _run(dossier, _envelope(dossier, key), key, tmp_path / "registry.sqlite3")
    assert result["freshness"] == "WITHIN_LOCAL_POLICY_WINDOW"
    assert result["key_lifecycle"] == "VALID_AT_VERIFICATION_TIME"
    assert result["qualification"] == "NOT_ESTABLISHED"


def test_expired_key_is_rejected(tmp_path):
    dossier, key = _dossier(), Ed25519PrivateKey.generate()
    with pytest.raises(RunnerTrustPolicyError, match="runner_key_expired"):
        _run(dossier, _envelope(dossier, key), key, tmp_path / "registry.sqlite3",
             trust_overrides={"not_after": "2026-10-11T00:00:00Z"})


def test_revoked_key_is_rejected(tmp_path):
    dossier, key = _dossier(), Ed25519PrivateKey.generate()
    with pytest.raises(RunnerTrustPolicyError, match="runner_key_revoked"):
        _run(dossier, _envelope(dossier, key), key, tmp_path / "registry.sqlite3",
             trust_overrides={"revoked_at": "2026-10-12T05:59:00Z"})


def test_provider_mismatch_is_rejected(tmp_path):
    dossier, key = _dossier(), Ed25519PrivateKey.generate()
    trust = RunnerTrustKey("another-provider", _public_bytes(key), "2026-10-01T00:00:00Z", "2027-01-01T00:00:00Z")
    with pytest.raises(RunnerTrustPolicyError, match="runner_provider_mismatch"):
        verify_with_runner_trust_policy(dossier, _envelope(dossier, key), trusted_keys={"policy-key": trust},
            database_path=tmp_path / "registry.sqlite3", now=datetime(2026, 10, 12, 6, 1, tzinfo=timezone.utc))


def test_stale_receipt_is_rejected(tmp_path):
    dossier, key = _dossier(), Ed25519PrivateKey.generate()
    with pytest.raises(RunnerTrustPolicyError, match="receipt_stale"):
        _run(dossier, _envelope(dossier, key), key, tmp_path / "registry.sqlite3", max_age=timedelta(seconds=30))


def test_future_receipt_is_rejected(tmp_path):
    dossier, key = _dossier(completed="2026-10-12T06:02:00Z"), Ed25519PrivateKey.generate()
    with pytest.raises(RunnerTrustPolicyError, match="receipt_timestamp_in_future"):
        _run(dossier, _envelope(dossier, key), key, tmp_path / "registry.sqlite3")


def test_naive_timestamp_is_rejected(tmp_path):
    dossier, key = _dossier(completed="2026-10-12T06:00:03"), Ed25519PrivateKey.generate()
    with pytest.raises(RunnerTrustPolicyError, match="timestamp_timezone_required"):
        _run(dossier, _envelope(dossier, key), key, tmp_path / "registry.sqlite3")


def test_policy_rejection_does_not_consume_nonce(tmp_path):
    dossier, key, path = _dossier(), Ed25519PrivateKey.generate(), tmp_path / "registry.sqlite3"
    envelope = _envelope(dossier, key)
    with pytest.raises(RunnerTrustPolicyError, match="receipt_stale"):
        _run(dossier, envelope, key, path, max_age=timedelta(seconds=30))
    assert _run(dossier, envelope, key, path)["valid"]


def test_negative_freshness_window_rejected(tmp_path):
    dossier, key = _dossier(), Ed25519PrivateKey.generate()
    with pytest.raises(RunnerTrustPolicyError, match="negative_freshness_window"):
        _run(dossier, _envelope(dossier, key), key, tmp_path / "registry.sqlite3", max_age=timedelta(seconds=-1))
