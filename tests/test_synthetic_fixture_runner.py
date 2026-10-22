import json
import subprocess
import sys
from pathlib import Path

import pytest

from shared.synthetic_fixture import (
    PROCESS_INPUT_SCHEMA_VERSION,
    run_synthetic_fixture,
)
from shared.synthetic_fixture_runner import (
    MAX_TIMEOUT_SECONDS,
    SyntheticFixtureRunnerError,
    run_synthetic_fixture_subprocess,
)


@pytest.mark.parametrize("mode", ["control", "countertest"])
def test_runner_captures_real_child_stdout_stderr_and_exit_code(mode):
    expected = run_synthetic_fixture(mode)

    actual = run_synthetic_fixture_subprocess(mode)

    assert actual["subprocess_started"] is True
    assert actual["execution_mode"] == "fixed_fixture_subprocess"
    assert actual["stdout_bytes"] == expected["stdout_bytes"]
    assert actual["stderr_bytes"] == expected["stderr_bytes"] == b""
    assert actual["exit_code"] == expected["exit_code"] == 0
    assert actual["expected_exit_code"] == 0
    assert actual["checks"] == expected["checks"]
    assert actual["passed"] is True
    assert actual["network_access"] is False
    assert actual["execution"]["status"] == "PASS"
    assert actual["execution"]["shell_used"] is False
    assert actual["execution"]["command_source"] == "repository_constant"
    assert actual["execution"]["environment_allowlisted"] is True
    assert actual["execution"]["temporary_working_directory"] is True
    assert actual["execution"]["resource_limits_applied"] is True
    # These flags intentionally avoid claiming a full network/filesystem sandbox.
    assert actual["execution"]["network_isolation_enforced"] is False
    assert actual["execution"]["filesystem_isolation_enforced"] is False
    assert actual["execution"]["resource_limits"]["stdout_capture_bytes"] > 0
    assert actual["execution"]["resource_limits"]["stderr_capture_bytes"] > 0

    process_input = json.loads(actual["input_bytes"].decode("utf-8"))
    assert process_input == {
        "schema_version": PROCESS_INPUT_SCHEMA_VERSION,
        "mode": mode,
    }
    assert actual["argv"][-1] == mode
    assert actual["argv"][-2] == "--subprocess-run"
    assert actual["argv"][1] == "-I"
    assert actual["toolchain"]["runner"] == "aegisforge-fixed-synthetic-subprocess-v1"
    assert actual["toolchain"]["network_isolation"] == "not_enforced"
    assert actual["toolchain"]["filesystem_isolation"] == "not_enforced"


@pytest.mark.parametrize("mode", [
    "", "shell", "control; arbitrary command", "../countertest", None, [], {},
])
def test_runner_rejects_non_allowlisted_modes_before_spawning(monkeypatch, mode):
    def unexpected_spawn(*args, **kwargs):
        pytest.fail("the runner must reject an invalid mode before process creation")

    monkeypatch.setattr(subprocess, "Popen", unexpected_spawn)
    with pytest.raises(
        SyntheticFixtureRunnerError,
        match="synthetic_fixture_mode_not_allowed",
    ):
        run_synthetic_fixture_subprocess(mode)


@pytest.mark.parametrize("timeout", [
    0, -1, True, float("inf"), float("nan"), MAX_TIMEOUT_SECONDS + 0.01,
])
def test_runner_rejects_unbounded_or_invalid_timeout_before_spawning(
    monkeypatch, timeout
):
    def unexpected_spawn(*args, **kwargs):
        pytest.fail("invalid timeout must be rejected before process creation")

    monkeypatch.setattr(subprocess, "Popen", unexpected_spawn)
    with pytest.raises(
        SyntheticFixtureRunnerError,
        match="synthetic_fixture_timeout_invalid",
    ):
        run_synthetic_fixture_subprocess("control", timeout_seconds=timeout)


def test_fixed_child_rejects_input_mode_mismatch():
    script = Path(__file__).parents[1] / "shared" / "synthetic_fixture.py"
    mismatched_input = json.dumps(
        {
            "schema_version": PROCESS_INPUT_SCHEMA_VERSION,
            "mode": "countertest",
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    process = subprocess.run(
        [
            sys.executable,
            "-I",
            str(script),
            "--subprocess-run",
            "control",
        ],
        input=mismatched_input,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5,
        check=False,
        shell=False,
        cwd=Path(__file__).parents[1],
        env={
            "HOME": str(Path(__file__).parents[1]),
            "TMPDIR": str(Path(__file__).parents[1]),
        },
    )
    assert process.returncode == 65
    assert process.stdout == b""
