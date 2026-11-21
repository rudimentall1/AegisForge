"""One-command acceptance check for the optional Bubblewrap fixture backend.

This checks the sandbox harness against the repository-owned synthetic fixture.
It does not execute target code or establish vulnerability reproduction.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from shared.isolated_synthetic_fixture_runner import (
    IsolatedFixtureRunnerError,
    run_isolated_synthetic_fixture,
)

MODES = ("control", "countertest")


def _git_commit() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=2,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = result.stdout.strip()
    return value if len(value) == 40 and all(c in "0123456789abcdef" for c in value) else None


def _bwrap_version() -> str | None:
    executable = shutil.which("bwrap")
    if not executable:
        return None
    try:
        result = subprocess.run(
            [executable, "--version"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=2,
            shell=False,
            env={},
        )
    except (OSError, subprocess.SubprocessError):
        return "present_but_version_unavailable"
    return result.stdout.strip()[:200]


def build_report() -> tuple[dict, int]:
    report: dict = {
        "schema_version": "aegisforge-bubblewrap-acceptance-v1",
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "FAIL",
        "scope": "fixed_repository_owned_synthetic_fixture_only",
        "target_code_executed": False,
        "vulnerability_reproduction_established": False,
        "runner_commit": _git_commit(),
        "platform": platform.platform(),
        "python_version": sys.version.split()[0],
        "bubblewrap_version": _bwrap_version(),
        "modes": {},
    }
    if not sys.platform.startswith("linux"):
        report["failure"] = "linux_required"
        return report, 1
    if not shutil.which("bwrap"):
        report["failure"] = "bubblewrap_unavailable_fail_closed"
        return report, 1

    for mode in MODES:
        try:
            result = run_isolated_synthetic_fixture(mode)
            stdout = result["stdout_bytes"]
            stderr = result["stderr_bytes"]
            checks = result["execution"]
            required_true = (
                "network_isolation_enforced",
                "filesystem_isolation_enforced",
                "network_namespace_checked",
                "read_only_system_tree_checked",
                "private_tmp_write_checked",
            )
            if (
                checks.get("status") != "PASS"
                or not all(checks.get(name) is True for name in required_true)
                or result.get("subprocess_started") is not True
            ):
                raise RuntimeError("required_isolation_check_missing")
            report["modes"][mode] = {
                "status": "PASS",
                "exit_code": result["exit_code"],
                "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                "stdout_bytes": len(stdout),
                "stderr_bytes": len(stderr),
                "elapsed_ms": checks.get("elapsed_ms"),
                "network_namespace_checked": True,
                "read_only_system_tree_checked": True,
                "private_tmp_write_checked": True,
            }
        except Exception as exc:
            report["modes"][mode] = {
                "status": "FAIL",
                "error": str(exc)[:500],
                "error_type": type(exc).__name__,
            }
            report["failure"] = f"{mode}_failed"
            return report, 1

    report["status"] = "PASS"
    report["acceptance_note"] = (
        "Both fixed fixture modes completed with runtime namespace and filesystem "
        "checks. This is harness-isolation evidence only, not target reproduction."
    )
    return report, 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        help="write the JSON acceptance report to this path instead of stdout",
    )
    args = parser.parse_args()
    report, exit_code = build_report()
    rendered = json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        print(json.dumps({
            "status": report["status"],
            "report_path": str(args.output),
            "failure": report.get("failure"),
        }, sort_keys=True))
    else:
        sys.stdout.write(rendered)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
