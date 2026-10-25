"""Fail-closed tests for the optional bubblewrap fixture backend."""
import shutil

import pytest

from shared.synthetic_fixture import run_synthetic_fixture
from shared import isolated_synthetic_fixture_runner as sandbox


def test_isolated_runner_fails_closed_when_bubblewrap_is_missing(monkeypatch):
    def unexpected_spawn(*args, **kwargs):
        pytest.fail("must not spawn an unisolated fallback")

    monkeypatch.setattr(sandbox.shutil, "which", lambda name: None)
    monkeypatch.setattr(sandbox.subprocess, "Popen", unexpected_spawn)

    with pytest.raises(
        sandbox.IsolatedFixtureRunnerError,
        match="bubblewrap_unavailable_fail_closed",
    ):
        sandbox.run_isolated_synthetic_fixture("control")


@pytest.mark.parametrize("mode", ["", "shell", "../fixture", None, {}, []])
def test_isolated_runner_rejects_non_fixture_modes_before_spawning(monkeypatch, mode):
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: "/usr/bin/bwrap")

    def unexpected_spawn(*args, **kwargs):
        pytest.fail("invalid mode must be rejected before process creation")

    monkeypatch.setattr(sandbox.subprocess, "Popen", unexpected_spawn)
    with pytest.raises(
        sandbox.IsolatedFixtureRunnerError,
        match="isolated_fixture_mode_not_allowed",
    ):
        sandbox.run_isolated_synthetic_fixture(mode)


def test_bwrap_profile_enforces_network_and_read_only_filesystem():
    command = sandbox._build_bwrap_command(
        bwrap_path="/usr/bin/bwrap",
        python_path="/usr/bin/python3",
        fixture_path="/repo/shared/synthetic_fixture.py",
        mode="control",
        expected_net_ns=12345,
        write_probe="aegisforge-probe-test",
    )
    assert "--unshare-net" in command
    assert "--unshare-user" in command
    assert "--unshare-pid" in command
    assert "--cap-drop" in command and command[command.index("--cap-drop") + 1] == "ALL"
    assert command[command.index("--ro-bind") + 1:command.index("--ro-bind") + 3] == [
        "/usr", "/usr"
    ]
    assert "--tmpfs" in command and command[command.index("--tmpfs") + 1] == "/tmp"
    assert "/repo/shared/synthetic_fixture.py" in command
    assert "--" in command
    # Never bind the host root, home directories, repository tree, or arbitrary argv.
    assert "/" not in command[command.index("--ro-bind") + 1:command.index("--ro-bind") + 3]
    assert "/root" not in command and "/home" not in command


@pytest.mark.skipif(shutil.which("bwrap") is None, reason="bubblewrap is not installed")
@pytest.mark.parametrize("mode", ["control", "countertest"])
def test_bubblewrap_backend_runs_only_the_fixture_with_isolation_checks(mode):
    result = sandbox.run_isolated_synthetic_fixture(mode)
    assert result["execution_mode"] == "bubblewrap_isolated_fixed_fixture"
    assert result["execution"]["network_isolation_enforced"] is True
    assert result["execution"]["filesystem_isolation_enforced"] is True
    assert result["execution"]["network_namespace_checked"] is True
    assert result["execution"]["read_only_system_tree_checked"] is True
    assert result["execution"]["private_tmp_write_checked"] is True
    assert result["stdout_bytes"] == run_synthetic_fixture(mode)["stdout_bytes"]
    assert result["stderr_bytes"] == run_synthetic_fixture(mode)["stderr_bytes"]
    assert result["execution"]["status"] == "PASS"
    assert result["synthetic_fixture"] is True
    assert result["subprocess_started"] is True
