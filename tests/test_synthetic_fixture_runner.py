import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from shared.synthetic_fixture import (
    PROCESS_INPUT_SCHEMA_VERSION,
    run_synthetic_fixture,
)
from shared.synthetic_fixture_runner import (
    MAX_CAPTURE_BYTES,
    MAX_TIMEOUT_SECONDS,
    SyntheticFixtureRunnerError,
    _capture_bounded,
    _kill_process_group,
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
    assert actual["execution"]["network_isolation_status"] == "NOT_ENFORCED"
    assert actual["execution"]["filesystem_isolation_status"] == "NOT_ENFORCED"
    assert actual["execution"]["network_access_observed"] == "NONE_IN_FIXED_FIXTURE"
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
    assert actual["toolchain"]["network_access_observed"] == "none_in_fixed_fixture"


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


@pytest.mark.parametrize("stream_name", ["stdout", "stderr"])
def test_pipe_capture_kills_output_that_exceeds_the_hard_limit(stream_name):
    source = (
        "import sys; "
        f"sys.{stream_name}.buffer.write(b'x' * {MAX_CAPTURE_BYTES + 4096}); "
        f"sys.{stream_name}.flush()"
    )
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", source],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        start_new_session=True,
        shell=False,
    )
    try:
        with pytest.raises(
            SyntheticFixtureRunnerError,
            match=f"synthetic_fixture_{stream_name}_limit_exceeded",
        ):
            _capture_bounded(process, deadline=time.monotonic() + 3.0)
    finally:
        _kill_process_group(process)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


def test_pipe_capture_timeout_is_a_controlled_failure_and_can_be_killed():
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        start_new_session=True,
        shell=False,
    )
    started = time.monotonic()
    try:
        with pytest.raises(
            SyntheticFixtureRunnerError,
            match="synthetic_fixture_timeout",
        ):
            _capture_bounded(process, deadline=time.monotonic() + 0.05)
    finally:
        _kill_process_group(process)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
    assert time.monotonic() - started < 1.5
