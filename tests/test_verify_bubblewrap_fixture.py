"""Tests for the standalone Bubblewrap acceptance command's exit contract."""
from __future__ import annotations

from scripts import verify_bubblewrap_fixture as acceptance


def test_acceptance_fails_closed_when_bubblewrap_is_missing(monkeypatch):
    monkeypatch.setattr(acceptance.sys, "platform", "linux")
    monkeypatch.setattr(acceptance.shutil, "which", lambda name: None)
    report, exit_code = acceptance.build_report()

    assert exit_code == 1
    assert report["status"] == "FAIL"
    assert report["failure"] == "bubblewrap_unavailable_fail_closed"
    assert report["target_code_executed"] is False
    assert report["vulnerability_reproduction_established"] is False


def test_acceptance_requires_both_runtime_isolation_checks(monkeypatch):
    monkeypatch.setattr(acceptance.sys, "platform", "linux")
    monkeypatch.setattr(acceptance.shutil, "which", lambda name: "/usr/bin/bwrap")
    monkeypatch.setattr(acceptance, "_bwrap_version", lambda: "bubblewrap test version")
    calls = []

    def fake_run(mode):
        calls.append(mode)
        return {
            "stdout_bytes": b"fixture-output",
            "stderr_bytes": b"",
            "exit_code": 0,
            "subprocess_started": True,
            "execution": {
                "status": "PASS",
                "elapsed_ms": 2,
                "network_isolation_enforced": True,
                "filesystem_isolation_enforced": True,
                "network_namespace_checked": True,
                "read_only_system_tree_checked": True,
                "private_tmp_write_checked": True,
            },
        }

    monkeypatch.setattr(acceptance, "run_isolated_synthetic_fixture", fake_run)
    report, exit_code = acceptance.build_report()

    assert exit_code == 0
    assert report["status"] == "PASS"
    assert calls == ["control", "countertest"]
    assert all(report["modes"][mode]["status"] == "PASS" for mode in calls)
    assert report["target_code_executed"] is False
    assert report["vulnerability_reproduction_established"] is False


def test_acceptance_fails_if_runtime_isolation_check_is_missing(monkeypatch):
    monkeypatch.setattr(acceptance.sys, "platform", "linux")
    monkeypatch.setattr(acceptance.shutil, "which", lambda name: "/usr/bin/bwrap")
    monkeypatch.setattr(acceptance, "_bwrap_version", lambda: "bubblewrap test version")

    def fake_run(mode):
        return {
            "stdout_bytes": b"fixture-output",
            "stderr_bytes": b"",
            "exit_code": 0,
            "subprocess_started": True,
            "execution": {
                "status": "PASS",
                "elapsed_ms": 2,
                "network_isolation_enforced": True,
                "filesystem_isolation_enforced": True,
                "network_namespace_checked": True,
                "read_only_system_tree_checked": True,
                "private_tmp_write_checked": False,
            },
        }

    monkeypatch.setattr(acceptance, "run_isolated_synthetic_fixture", fake_run)
    report, exit_code = acceptance.build_report()

    assert exit_code == 1
    assert report["status"] == "FAIL"
    assert report["failure"] == "control_failed"
    assert report["modes"]["control"]["status"] == "FAIL"
