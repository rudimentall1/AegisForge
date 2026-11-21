import json

import pytest

from shared.synthetic_fixture import FIXTURE_SCHEMA_VERSION, run_synthetic_fixture


def test_control_fixture_preserves_invariant_and_is_deterministic():
    first = run_synthetic_fixture("control")
    second = run_synthetic_fixture("control")

    assert first == second
    assert first["schema_version"] == FIXTURE_SCHEMA_VERSION
    assert first["passed"] is True
    assert first["checks"] == {"invariant_preserved": True}
    assert first["exit_code"] == first["expected_exit_code"] == 0
    assert b"invariant_preserved=true" in first["stdout_bytes"]
    assert b"invariant_preserved=false" not in first["stdout_bytes"]
    assert first["stderr_bytes"] == b""
    assert first["subprocess_started"] is False
    assert first["network_access"] is False

    input_payload = json.loads(first["input_bytes"])
    assert input_payload["expected_balance"] == input_payload["observed_balance"] == 100
    assert input_payload["seeded_violation"] is False


def test_countertest_fixture_detects_only_the_deliberately_seeded_violation():
    result = run_synthetic_fixture("countertest")

    assert result["passed"] is True
    assert result["checks"] == {"seeded_violation_detected": True}
    assert result["exit_code"] == result["expected_exit_code"] == 0
    assert b"seeded_violation_detected=true" in result["stdout_bytes"]
    assert b"seeded_violation_detected=false" not in result["stdout_bytes"]
    input_payload = json.loads(result["input_bytes"])
    assert input_payload["expected_balance"] == 100
    assert input_payload["observed_balance"] == 99
    assert input_payload["seeded_violation"] is True
    assert result["synthetic_fixture"] is True


@pytest.mark.parametrize("mode", ["", "execute", "shell", "control; arbitrary command", None, [], {}])
def test_synthetic_fixture_rejects_unknown_or_non_string_modes(mode):
    with pytest.raises(ValueError, match="synthetic_fixture_mode_not_allowed"):
        run_synthetic_fixture(mode)
