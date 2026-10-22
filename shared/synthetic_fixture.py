"""Fixed, deterministic in-process fixtures for the local-only evidence pipeline.

These fixtures exercise the EvidenceLedger and dossier path without launching a
process, evaluating bundle-supplied commands, using network APIs, or touching a
real protocol. Their output can validate the harness; it cannot establish target
behavior or a vulnerability.
"""
from __future__ import annotations

import json

FIXTURE_SCHEMA_VERSION = "aegisforge-synthetic-accounting-v1"
_ALLOWED_MODES = frozenset({"control", "countertest"})
_EXPECTED_BALANCE = 100


def _canonical_bytes(value: dict) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def run_synthetic_fixture(mode: str) -> dict:
    """Run one repository-owned state fixture in-process and return raw outputs.

    `argv` is descriptive metadata for the dossier, not a command passed to an
    operating system. Only the fixed modes in this module are accepted.
    """
    if not isinstance(mode, str) or mode not in _ALLOWED_MODES:
        raise ValueError("synthetic_fixture_mode_not_allowed")

    expected_balance = _EXPECTED_BALANCE
    observed_balance = (
        _EXPECTED_BALANCE if mode == "control" else _EXPECTED_BALANCE - 1
    )
    invariant_preserved = observed_balance == expected_balance
    seeded_violation_detected = observed_balance != expected_balance
    passed = (
        invariant_preserved if mode == "control" else seeded_violation_detected
    )

    fixture_input = {
        "schema_version": FIXTURE_SCHEMA_VERSION,
        "mode": mode,
        "expected_balance": expected_balance,
        "observed_balance": observed_balance,
        "seeded_violation": mode == "countertest",
    }
    if mode == "control":
        output = (
            "SYNTHETIC_FIXTURE fixture=accounting-v1 mode=control "
            f"invariant_preserved={str(invariant_preserved).lower()} "
            f"expected_balance={expected_balance} observed_balance={observed_balance}\n"
        )
        checks = {"invariant_preserved": invariant_preserved}
    else:
        output = (
            "SYNTHETIC_FIXTURE fixture=accounting-v1 mode=countertest "
            f"seeded_violation_detected={str(seeded_violation_detected).lower()} "
            f"expected_balance={expected_balance} observed_balance={observed_balance}\n"
        )
        checks = {"seeded_violation_detected": seeded_violation_detected}

    return {
        "schema_version": FIXTURE_SCHEMA_VERSION,
        "mode": mode,
        "input_bytes": _canonical_bytes(fixture_input),
        "stdout_bytes": output.encode("utf-8"),
        "stderr_bytes": b"",
        "exit_code": 0 if passed else 1,
        "expected_exit_code": 0,
        "argv": ["aegisforge-synthetic-fixture", mode],
        "toolchain": {
            "python": "3.10",
            "fixture": FIXTURE_SCHEMA_VERSION,
        },
        "checks": checks,
        "passed": passed,
        "synthetic_fixture": True,
        "network_access": False,
        "subprocess_started": False,
    }
